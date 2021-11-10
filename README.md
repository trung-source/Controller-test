# Controller-test

`ryu-manager --observe-links Controller_test.py`

Chay va luu file output
`ryu-manager --observe-links Controller_test.py |& tee output.txt`

Topo.py: Topology voi 1 host tren 1 switch. La do hinh loop voi 5 switch
topo.py: La topology tren voi 2-3 host voi tung switch
    + Default la 3 host
    + set bien `third_host = False` trong file de chay voi truong hop 2 host tren tung switch
    
