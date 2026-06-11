package main
import ("fmt";"net";"os";"strconv";"time";"syscall";"errors")
func main(){
  port,_ := strconv.Atoi(os.Args[1])
  _, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(port), 300*time.Millisecond)
  if err==nil { fmt.Println("MX rc=0 errno=0(ok)"); return }
  var se syscall.Errno
  if errors.As(err, &se) { fmt.Printf("MX rc=-1 errno=%d(%s)\n", int(se), se.Error()); os.Exit(int(se)) }
  fmt.Printf("MX rc=-1 errno=?(%v)\n", err); os.Exit(1)
}
