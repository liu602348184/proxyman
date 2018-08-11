/*
* @Author: liuyujie
* @Date:   2018-08-12 03:00:14
* @Last Modified by:   liuyujie
* @Last Modified time: 2018-08-12 03:09:09
*/
package main
import(
    "log"
    "sync"
)
func main(){
    var wg sync.WaitGroup
    c := make(chan string, 2)
    wg.Add(1)

    go func(ch chan string) {
        str := <- ch
        log.Println("chan1")
        log.Println(str)
        wg.Done()
    }(c)

    go func(ch chan string) {
        str := <- ch
        log.Println("chan2")
        log.Println(str)
        wg.Done()
    }(c)

    c <- "test"
    wg.Wait()
}