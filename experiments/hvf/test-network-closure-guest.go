// SPDX-License-Identifier: Apache-2.0
// Dedicated guest overlay; does not change the general Linux fixture.
package main
import("bytes";"crypto/sha256";"encoding/json";"fmt";"io";"net";"net/http";"os";"strconv";"strings";"sync";"syscall";"time")
func main(){
 cmd,_:=os.ReadFile("/proc/cmdline");host:="";port:="";count:=64;workers:=8
 for _,a:=range strings.Fields(string(cmd)){if strings.HasPrefix(a,"closure.host="){host=strings.TrimPrefix(a,"closure.host=")};if strings.HasPrefix(a,"closure.port="){port=strings.TrimPrefix(a,"closure.port=")};if strings.HasPrefix(a,"closure.count="){count,_=strconv.Atoi(strings.TrimPrefix(a,"closure.count="))};if strings.HasPrefix(a,"closure.workers="){workers,_=strconv.Atoi(strings.TrimPrefix(a,"closure.workers="))}}
 var wg sync.WaitGroup;var mu sync.Mutex;var failures []string;total:=0;byteCount:=0
 for w:=0;w<workers;w++{wg.Add(1);go func(w int){defer wg.Done();for j:=0;j<count;j++{
 id:=w*count+j;sizes:=[]int{0,11,1460,4096,65536,262144};size:=sizes[id%len(sizes)];if strings.Contains(string(cmd),"closure.small=1"){size=11};want:=make([]byte,size);for k:=range want{want[k]=byte((id*31+k*17)%251)}
 tr:=&http.Transport{DisableKeepAlives:true};client:=&http.Client{Transport:tr,Timeout:8*time.Second}
 r,e:=client.Get(fmt.Sprintf("http://%s:%s/%d/%d",host,port,id,size));var got []byte
 if e==nil{got,e=io.ReadAll(r.Body);r.Body.Close();if e==nil&&(r.StatusCode!=200||!bytes.Equal(got,want)){e=fmt.Errorf("content id=%d len=%d expected=%d sha=%x",id,len(got),size,sha256.Sum256(got))}};tr.CloseIdleConnections()
 mu.Lock();if e!=nil{failures=append(failures,fmt.Sprint(e))}else{total++;byteCount+=len(got)};mu.Unlock()
 }}(w)};wg.Wait()
 udpOK:=0
 for j:=0;j<64;j++{c,e:=net.DialTimeout("udp","10.0.2.2:"+port,time.Second);if e!=nil{failures=append(failures,e.Error());break};c.SetDeadline(time.Now().Add(time.Second));payload:=[]byte(fmt.Sprintf("udp-%04d",j));_,e=c.Write(payload);buf:=make([]byte,100);n:=0;if e==nil{n,e=c.Read(buf)};c.Close();if e!=nil||!bytes.Equal(payload,buf[:n]){failures=append(failures,fmt.Sprintf("udp %d %v",j,e))}else{udpOK++}}
 b,_:=json.Marshal(map[string]any{"http_ok":total,"http_expected":count*workers,"bytes":byteCount,"udp_ok":udpOK,"failures":failures});fmt.Println("NETWORK_CLOSURE "+string(b));syscall.Sync();syscall.Reboot(syscall.LINUX_REBOOT_CMD_POWER_OFF)
}
