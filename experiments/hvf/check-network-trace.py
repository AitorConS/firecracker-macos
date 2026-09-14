#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Compare traced host socket bytes, broker frames and VirtIO RX byte streams."""
import argparse,collections,hashlib,json,struct
from pathlib import Path
def digest(b):return hashlib.sha256(b).hexdigest()
def check(path):
    records={};order=[]
    for line in path.read_text(errors='replace').splitlines():
        if not line.startswith('NETTRACE '):continue
        _,pid,tag,event,fd,length,offset,*data=line.split();key=(pid,tag,event);offset=int(offset)
        if key not in records:records[key]=[tag,int(fd),int(length),bytearray()];order.append(key)
        record=records[key];assert offset==len(record[3]),(key,offset,len(record[3]));record[3].extend(bytes.fromhex(data[0]) if data else b'')
    active={};streams=[];frames=collections.defaultdict(list);scm=0;eofs=0
    for key in order:
        tag,fd,length,data=records[key];assert len(data)==max(length,0)
        conn=(key[0],fd)
        if tag=='SCM_TCP':
            assert struct.unpack('i',data)[0]>=0;scm+=1
            if conn in active:streams.append(bytes(active.pop(conn)))
            active[conn]=bytearray()
        if tag=='TCP_RECV':
            if length>0:assert conn in active;active[conn].extend(data)
            if length==0:eofs+=1
        if tag in ('BROKER_RX','VIRTIO_RX'):frames[tag].append(bytes(data))
    streams.extend(bytes(v) for v in active.values());streams=[s for s in streams if s]
    # Compare entire Ethernet frames, including duplicate TCP retransmissions.
    broker=collections.Counter(map(digest,frames['BROKER_RX']));virtio=collections.Counter(map(digest,frames['VIRTIO_RX']));missing=broker-virtio;extra=virtio-broker
    assert not extra,extra
    assert scm>0 and streams and frames['VIRTIO_RX'],'missing trace evidence'
    def reassemble(packets):
        flows=collections.defaultdict(dict)
        for p in packets:
            if len(p)<54 or p[12:14]!=b'\x08\x00' or p[23]!=6:continue
            ihl=(p[14]&15)*4;t=14+ihl;thl=(p[t+12]>>4)*4;end=14+int.from_bytes(p[16:18],'big');payload=p[t+thl:end]
            if not payload:continue
            ports=p[t:t+4];seq=int.from_bytes(p[t+4:t+8],'big')
            for i,b in enumerate(payload):
                pos=(seq+i)&0xffffffff
                if pos in flows[ports]:assert flows[ports][pos]==b
                flows[ports][pos]=b
        result=[]
        for positions in flows.values():
            keys=sorted(positions);assert len(keys)==keys[-1]-keys[0]+1
            result.append(bytes(positions[k] for k in keys))
        return result
    expected=collections.Counter(map(digest,streams))
    assert expected==collections.Counter(map(digest,reassemble(frames['BROKER_RX'])))
    assert expected==collections.Counter(map(digest,reassemble(frames['VIRTIO_RX'])))
    return {'file':str(path),'scm_transfers':scm,'tcp_streams':len(streams),'recv_bytes':sum(map(len,streams)),'eof_reads':eofs,'broker_frames':len(frames['BROKER_RX']),'virtio_frames':len(frames['VIRTIO_RX']),'undelivered_frames':sum(missing.values()),'three_stage_streams_equal':True,'stream_sha256':list(expected.elements())}
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('directory',type=Path);a=p.parse_args();result=[check(f) for f in sorted(a.directory.glob('*.native.log'))];assert result;(a.directory/'trace-verdict.json').write_text(json.dumps(result,indent=2));print(json.dumps(result,indent=2))
