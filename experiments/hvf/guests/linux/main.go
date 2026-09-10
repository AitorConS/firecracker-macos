// SPDX-License-Identifier: Apache-2.0
package main
import("bytes";"encoding/json";"encoding/binary";"fmt";"io";"net";"net/http";"os";"os/signal";"runtime";"strconv";"strings";"syscall";"time")
func main(){
 fail:=func(e error){if e!=nil {panic(e)}}
 disk,e:=os.OpenFile("/dev/vda",os.O_RDWR,0);fail(e)
 b:=make([]byte,512);_,e=disk.ReadAt(b,0);fail(e)
 if !strings.HasPrefix(string(b),"HVF_GENERIC_BLOCK_V1"){panic("wrong block contents")}
 _,e=disk.ReadAt(b,512);fail(e);n,_:=strconv.Atoi(strings.Trim(string(b),"\x00\n "));n++
 b=make([]byte,512);copy(b,fmt.Sprint(n));_,e=disk.WriteAt(b,512);fail(e);fail(disk.Sync());fail(disk.Close())
 mac,e:=os.ReadFile("/sys/class/net/eth0/address");fail(e)
 kernel,e:=os.ReadFile("/proc/version");fail(e)
 shutdown:=func(){syscall.Sync();fail(syscall.Reboot(syscall.LINUX_REBOOT_CMD_POWER_OFF))}
 signals:=make(chan os.Signal,1);signal.Notify(signals,syscall.SIGTERM);go func(){<-signals;shutdown()}()
 go func(){s,e:=net.ListenPacket("udp",":9001");fail(e);for {b:=make([]byte,2048);n,a,e:=s.ReadFrom(b);fail(e);_,e=s.WriteTo(b[:n],a);fail(e)}}()
 cmdline,e:=os.ReadFile("/proc/cmdline");fail(e)
 if !strings.Contains(string(cmdline),"vmm.ignore_power=1") {go func(){
  f,e:=os.Open("/dev/input/event0");fail(e);defer f.Close();event:=make([]byte,24)
  for{_,e=io.ReadFull(f,event);fail(e);if binary.LittleEndian.Uint16(event[16:18])==1 && binary.LittleEndian.Uint16(event[18:20])==116 && binary.LittleEndian.Uint32(event[20:24])==1 {
   d,e:=os.OpenFile("/dev/vda",os.O_RDWR,0);fail(e);_,e=d.WriteAt([]byte("POWER_BUTTON_SYNCED"),1024);fail(e);fail(d.Sync());d.Close();fmt.Println("POWER_BUTTON_RECEIVED");shutdown();return
  }}
 }()}
 for _,arg:=range strings.Fields(string(cmdline)) {if strings.HasPrefix(arg,"vmm.callback=") {
  data,_:=json.Marshal(map[string]any{"count":n,"mac":strings.TrimSpace(string(mac)),"cpus":runtime.NumCPU()})
  response,e:=http.Post(strings.TrimPrefix(arg,"vmm.callback="),"application/json",bytes.NewReader(data));fail(e)
  reply,e:=io.ReadAll(response.Body);fail(e);response.Body.Close();if string(reply)!="outbound-ok"{panic("bad callback")};shutdown();return
 }}
 http.HandleFunc("/",func(w http.ResponseWriter,r *http.Request){json.NewEncoder(w).Encode(map[string]any{"kernel":strings.TrimSpace(string(kernel)),"arch":runtime.GOARCH,"cpus":runtime.NumCPU(),"count":n,"mac":strings.TrimSpace(string(mac))})})
 http.HandleFunc("/echo",func(w http.ResponseWriter,r *http.Request){io.Copy(w,r.Body)})
 http.HandleFunc("/shutdown",func(w http.ResponseWriter,r *http.Request){fmt.Fprint(w,"bye");go func(){time.Sleep(100*time.Millisecond);shutdown()}()})
 fmt.Println("LINUX_GENERIC_READY")
 fail(http.ListenAndServe(":9000",nil))
}
