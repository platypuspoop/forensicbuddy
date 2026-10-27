// ForensicBuddy browser-only connection indexing.
// Parsed connection summaries are derived records, NOT original forensic evidence.
// No external libraries, network requests, application payload decoding or file persistence.
const CONNECTION_LIMIT = 3000;
const CAPTURE_PACKET_LIMIT = 100000;
const CAPTURE_SIZE_LIMIT = 50 * 1024 * 1024;
const CONN_SOURCE_TYPES = new Set(["PCAP", "PCAPNG", "NetFlow"]);

function connectionTime(value){
  if(value===null || value===undefined || value==="")return "";
  const s=String(value).trim();
  if(/^\d{10}(?:\.\d+)?$/.test(s)){const d=new Date(Number(s)*1000);return isFinite(d.getTime())?d.toISOString():""}
  if(/^\d{13}$/.test(s)){const d=new Date(Number(s));return isFinite(d.getTime())?d.toISOString():""}
  const d=new Date(s);return isFinite(d.getTime())?d.toISOString():"";
}
function connectionIP4(data,pos){
  if(pos<0 || pos+4>data.length)return "";
  return [data[pos],data[pos+1],data[pos+2],data[pos+3]].join(".");
}
function connectionIP6(data,pos){
  if(pos<0 || pos+16>data.length)return "";
  const groups=[];
  for(let k=0;k<16;k+=2)groups.push((data[pos+k]*256+data[pos+k+1]).toString(16));
  // RFC 5952-style zero compression for display. Full form is equally valid.
  let start=-1,count=0;
  for(let i=0;i<8;){if(groups[i]!=="0"){i++;continue}let end=i;while(end<8&&groups[end]==="0")end++;if(end-i>count&&end-i>=2){start=i;count=end-i}i=end}
  if(start<0)return groups.join(":");
  const before=groups.slice(0,start).join(":"),after=groups.slice(start+count).join(":");
  return (before?before:"")+"::"+(after?after:"");
}
function captureTransport(data,linkType,time,originalLength){
  let pos=0,type=0;
  if(linkType===1){ // Ethernet; common 802.1Q/QinQ VLAN tags
    if(data.length<14)return null;
    type=(data[12]<<8)|data[13];pos=14;
    for(let i=0;i<3 && [0x8100,0x88a8,0x9100].includes(type);i++){
      if(pos+4>data.length)return null;
      type=(data[pos+2]<<8)|data[pos+3];pos+=4;
    }
  }else if(linkType===101){type=(data[0]>>4)===6?0x86dd:0x0800;pos=0}
  else if(linkType===113){ // Linux cooked v1
    if(data.length<16)return null;
    type=(data[14]<<8)|data[15];pos=16;
  }else if(linkType===276){ // Linux cooked v2
    if(data.length<20)return null;
    type=(data[0]<<8)|data[1];pos=20;
  }else return null;
  let src="",dst="",protocolNumber=0,fragment=false;
  if(type===0x0800){
    if(pos+20>data.length||data[pos]>>4!==4)return null;
    const len=(data[pos]&15)*4;
    if(len<20 || pos+len>data.length)return null;
    protocolNumber=data[pos+9];
    src=connectionIP4(data,pos+12);dst=connectionIP4(data,pos+16);
    fragment=((data[pos+6]&0x1f)!==0||data[pos+7]!==0);
    pos+=len;
  }else if(type===0x86dd){
    if(pos+40>data.length||data[pos]>>4!==6)return null;
    src=connectionIP6(data,pos+8);dst=connectionIP6(data,pos+24);
    protocolNumber=data[pos+6];pos+=40;
    for(let j=0;j<8&&[0,43,44,51,60,135].includes(protocolNumber);j++){
      if(pos+2>data.length)return null;
      const next=data[pos];
      let length=(data[pos+1]+1)*8;
      if(protocolNumber===44){
        if(pos+8>data.length)return null;
        fragment=((data[pos+2]&0xf8)!==0 || ((data[pos+3]&1)!==0));
        length=8;
      }
      if(protocolNumber===51)length=(data[pos+1]+2)*4;
      if(pos+length>data.length)return null;
      pos+=length;protocolNumber=next;
    }
  }else return null;
  const protocol=({6:"TCP",17:"UDP",1:"ICMP",58:"ICMPv6",47:"GRE",50:"ESP",51:"AH",132:"SCTP"})[protocolNumber]||"IP-"+protocolNumber;
  let srcPort="",dstPort="";
  if(!fragment && [6,17,132].includes(protocolNumber) && pos+4<=data.length){
    srcPort=String((data[pos]<<8)|data[pos+1]);
    dstPort=String((data[pos+2]<<8)|data[pos+3]);
  }
  return {src,dst,srcPort,dstPort,protocol,time,bytes:originalLength,
    packets:1,country:"",metric:"Captured frame bytes",countKind:"Captured packets"};
}
function connectionKey(f){
  return [f.src,f.srcPort,f.dst,f.dstPort,f.protocol].join("|");
}
function addConnection(aggregated,f,limit=CONNECTION_LIMIT){
  if(!f.src||!f.dst)return false;
  const key=connectionKey(f);
  let c=aggregated.get(key);
  if(!c){
    if(aggregated.size>=limit)return false;
    c={key,src:f.src,dst:f.dst,srcPort:f.srcPort||"",dstPort:f.dstPort||"",
      protocol:f.protocol||"Unknown",firstSeen:"",lastSeen:"",bytes:null,packets:null,
      records:0,country:f.country||"",metric:f.metric||"Export-reported bytes",
      countKind:f.countKind||"Export-reported packets"};
    aggregated.set(key,c);
  }
  c.records++;
  if(Number.isFinite(f.bytes)&&f.bytes>=0)c.bytes=(c.bytes??0)+f.bytes;
  if(Number.isFinite(f.packets)&&f.packets>=0)c.packets=(c.packets??0)+f.packets;
  if(f.country && !c.country)c.country=f.country;
  const tm=connectionTime(f.time);
  if(tm){
    if(!c.firstSeen||tm<c.firstSeen)c.firstSeen=tm;
    if(!c.lastSeen||tm>c.lastSeen)c.lastSeen=tm;
  }
  return true;
}
function extractNetflowConnections(rows){
  const map=new Map();let recognized=0,skipped=0,limitHit=false;
  for(const r of rows){
    const info=recordFacts(r);
    if(!info.src||!info.dst){skipped++;continue}
    recognized++;
    const packets=Number.isFinite(info.packets)&&info.packets>=0?info.packets:null;
    const bytes=Number.isFinite(info.bytes)&&info.bytes>=0?info.bytes:null;
    const f={src:info.src,dst:info.dst,srcPort:info.srcPort,dstPort:info.dstPort,
      protocol:info.protocol||"Unknown",bytes,packets,country:info.country||"",
      time:bestTime(r),metric:"Export-reported bytes",countKind:"Export-reported packets"};
    if(!addConnection(map,f))limitHit=true;
  }
  return {connections:Array.from(map.values()),recognized,skipped,
    warning:limitHit?"Connection index limited to "+CONNECTION_LIMIT+" unique directional 5-tuples. Narrow the source export to prevent omitted records.":""};
}
function parseCaptureFile(file){
  if(file.size>CAPTURE_SIZE_LIMIT)throw new Error("Capture exceeds browser prototype 50 MB parsing limit. Split it or use a local forensic workstation.");
  return file.arrayBuffer().then(buffer=>parseCaptureBytes(buffer,file.name));
}
function parseCaptureBytes(buffer,name="capture.pcap"){
  const data=new Uint8Array(buffer),view=new DataView(buffer);
  if(data.length<24)throw new Error("Capture is too short.");
  const map=new Map();
  let processed=0,decoded=0,skipped=0,unknownLink=0,limited=false;
  function packet(bytes,linkType,time,length){
    processed++;
    const record=captureTransport(bytes,linkType,time,length);
    if(!record){skipped++;if(![1,101,113,276].includes(linkType))unknownLink++;return}
    decoded++;
    if(!addConnection(map,record))limited=true;
  }
  function u16(offset,le){if(offset<0||offset+2>data.length)throw new Error("Truncated capture");return view.getUint16(offset,le)}
  function u32(offset,le){if(offset<0||offset+4>data.length)throw new Error("Truncated capture");return view.getUint32(offset,le)}
  const magic=Array.from(data.slice(0,4)).map(x=>x.toString(16).padStart(2,"0")).join("");
  let label="";
  if(["d4c3b2a1","a1b2c3d4","4d3cb2a1","a1b23c4d"].includes(magic)){
    const le=magic==="d4c3b2a1"||magic==="4d3cb2a1",nano=magic==="4d3cb2a1"||magic==="a1b23c4d";
    const major=u16(4,le);
    if(major!==2)throw new Error("Unsupported PCAP file version");
    const linkType=u32(20,le)&0xffff;
    let pos=24;label="PCAP";
    while(pos+16<=data.length && processed<CAPTURE_PACKET_LIMIT){
      const sec=u32(pos,le),frac=u32(pos+4,le),capLen=u32(pos+8,le),wireLen=u32(pos+12,le);
      pos+=16;
      if(capLen>data.length-pos)throw new Error("Truncated PCAP packet at offset "+pos);
      const ms=sec*1000+frac/(nano?1e6:1e3);
      const t=Number.isFinite(ms)&&ms>=0&&ms<8.64e15?new Date(ms).toISOString():"";
      packet(data.subarray(pos,pos+capLen),linkType,t,wireLen||capLen);
      pos+=capLen;
    }
    if(processed>=CAPTURE_PACKET_LIMIT&&pos<data.length)limited=true;
  }else if(magic==="0a0d0d0a"){
    let pos=0,le=true,interfaces=[];
    label="PCAPNG";
    while(pos+12<=data.length&&processed<CAPTURE_PACKET_LIMIT){
      const section=Array.from(data.subarray(pos,pos+4)).map(x=>x.toString(16).padStart(2,"0")).join("");
      if(section==="0a0d0d0a"){
        if(pos+12>data.length)throw new Error("Truncated PCAPNG section");
        const order=Array.from(data.subarray(pos+8,pos+12)).map(x=>x.toString(16).padStart(2,"0")).join("");
        if(order!=="4d3c2b1a"&&order!=="1a2b3c4d")throw new Error("Unsupported PCAPNG byte order");
        le=order==="4d3c2b1a";interfaces=[];
      }
      const type=u32(pos,le),size=u32(pos+4,le);
      if(size<12||size%4!==0||pos+size>data.length||u32(pos+size-4,le)!==size)
        throw new Error("Malformed PCAPNG block at offset "+pos);
      if(type===1){
        const link=u16(pos+8,le);let resolution=1e-6;
        for(let o=pos+16;o+4<=pos+size-4;){
          const code=u16(o,le),length=u16(o+2,le);o+=4;
          if(code===0)break;
          if(o+length>pos+size-4)break;
          if(code===9&&length>=1){const x=data[o];resolution=x&128?2**-(x&127):10**-x;}
          o+=(length+3)&~3;
        }
        interfaces.push({link,resolution});
      }else if(type===6 && size>=32){
        const id=u32(pos+8,le),hi=u32(pos+12,le),lo=u32(pos+16,le),capLen=u32(pos+20,le),wireLen=u32(pos+24,le);
        if(pos+28+capLen>pos+size-4)throw new Error("Malformed PCAPNG packet");
        const iface=interfaces[id];
        if(iface){
          const ms=(hi*4294967296+lo)*iface.resolution*1000;
          const time=Number.isFinite(ms)&&ms>=0&&ms<8.64e15?new Date(ms).toISOString():"";
          packet(data.subarray(pos+28,pos+28+capLen),iface.link,time,wireLen||capLen);
        }else{skipped++}
      }
      pos+=size;
    }
    if(processed>=CAPTURE_PACKET_LIMIT&&pos<data.length)limited=true;
  }else throw new Error("Not a recognized .pcap or .pcapng capture file.");
  const warnings=[];
  if(limited)warnings.push("Capture truncated at "+CAPTURE_PACKET_LIMIT+" decoded packets or "+CONNECTION_LIMIT+" unique flows; results are incomplete.");
  if(skipped)warnings.push(skipped+" packet(s) were not interpreted (non-IP, truncation or unsupported link types).");
  if(unknownLink)warnings.push("Unsupported link-layer types were encountered; those packets were excluded.");
  return {parser:label,parsedRecords:processed,connections:Array.from(map.values()),
    warning:warnings.join(" "),captureStats:{processed,decoded,skipped,unknownLink,limited}};
}
function publicIp(ip){
  // Only classify address scope, not geolocation or threat status.
  const x=String(ip).trim();
  if(x.includes(":"))return !(/^(::1|::|fe[89ab]|fc|fd|ff)/i.test(x)||x.startsWith("2001:db8:"));
  const a=x.split(".").map(Number);
  if(a.length!==4||a.some(n=>!Number.isInteger(n)||n<0||n>255))return false;
  const [p,q,r]=a;
  if(p===0||p===10||p===127||p>=224||p===192&&q===168||p===172&&q>=16&&q<=31||
    p===169&&q===254||p===100&&q>=64&&q<=127||p===192&&q===0||
    p===192&&q===0&&r===2||p===198&&(q===18||q===19||q===51)||
    p===203&&q===0&&r===113||p===192&&q===88)return false;
  return true;
}
function connectionMatches(conn,filter){
  const f=filter||{};
  const text=String(f.ip||"").trim().toLowerCase();
  if(text&&!(conn.src+" "+conn.dst).toLowerCase().includes(text))return false;
  const port=String(f.port||"").trim();
  if(port&&conn.srcPort!==port&&conn.dstPort!==port)return false;
  if(f.proto&&f.proto!=="all"&&conn.protocol!==f.proto)return false;
  const minBytes=Number(f.minBytes)||0;
  if(minBytes && (conn.bytes===null||conn.bytes<minBytes))return false;
  const start=connectionTime(f.from),end=connectionTime(f.to);
  if(start&&(!conn.lastSeen||conn.lastSeen<start))return false;
  if(end&&(!conn.firstSeen||conn.firstSeen>end))return false;
  const preset=f.preset||"all",dest=Number(conn.dstPort);
  if(preset==="external"&&!publicIp(conn.src)&&!publicIp(conn.dst))return false;
  if(preset==="dns"&&!(dest===53||Number(conn.srcPort)===53||dest===853))return false;
  if(preset==="web"&&![80,443,8080,8443].includes(dest))return false;
  if(preset==="remote"&&![22,3389,445,135,139,5985,5986,5900].includes(dest))return false;
  if(preset==="large"&&!(conn.bytes!==null&&conn.bytes>=1000000))return false;
  if(preset==="repeated"&&!(conn.records>=10||(conn.packets!==null&&conn.packets>=10)))return false;
  return true;
}
function connectionDescription(conn){
  const from=conn.src+(conn.srcPort?":"+conn.srcPort:""),to=conn.dst+(conn.dstPort?":"+conn.dstPort:"");
  const extra=[conn.protocol,conn.bytes===null?"bytes unavailable":conn.bytes.toLocaleString("en-US")+" "+conn.metric.toLowerCase(),
    conn.packets===null?"packet count unavailable":conn.packets.toLocaleString("en-US")+" "+conn.countKind.toLowerCase(),
    conn.records+" source record(s)"];
  if(conn.firstSeen||conn.lastSeen)extra.push("observed "+(conn.firstSeen||"unknown")+" to "+(conn.lastSeen||"unknown"));
  if(conn.country)extra.push("export-reported destination country: "+conn.country);
  return from+" → "+to+" | "+extra.join(" | ");
}
