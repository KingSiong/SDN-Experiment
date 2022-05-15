import requests
import json

def add_flow(dpid, dst_ip, out_port, priority=10):
    flow = {
        "dpid": dpid,
        "idle_timeout": 0,
        "hard_timeout": 0,
        "priority": priority,
        "match":{
            "dl_type": 2048,
            "nw_dst": dst_ip
        },
        "actions":[
            {
                "type":"OUTPUT",
                "port": out_port
            }
        ]
    }

    url = 'http://localhost:8080/stats/flowentry/add'
    ret = requests.post(
        url, headers={'Accept': 'application/json', 'Accept': 'application/json'}, data=json.dumps(flow))
    print(ret)


def install_path():
    '23 -> 4:s22:2 -> 2:s9:3 -> 3:s16:2 -> 3:s7:2 -> 3:25:2 -> 1'
    device = ["atla", "chic", "losa", "kans", "newy32aoa", "hous", "salt", "wash", "seat"]
    devive_to_dpid = {"atla": 4, "chic": 1, "losa": 9, "kans": 6, "newy32aoa": 3, "hous": 5, "salt": 7, "wash": 2,
                      "seat": 8}

    atla = {"xe-0/0/0": 2, "xe-0/1/3": 3, "xe-0/0/3": 4, "xe-1/0/1": 5, "xe-1/0/3": 6, "ge-6/0/0": 7, "ge-6/1/0": 8}
    chic = {"xe-1/1/3": 2, "xe-2/1/3": 3, "xe-0/1/0": 4, "xe-1/1/0": 5, "xe-1/1/2": 6, "xe-1/1/1": 7, "xe-1/0/1": 8,
            "xe-1/0/2": 9, "xe-1/0/3": 10}
    losa = {"ge-6/0/0": 2, "ge-6/1/0": 3, "xe-0/0/3": 4, "xe-0/1/3": 5, "xe-0/0/0": 6, "xe-0/1/0": 7}
    kans = {"xe-0/0/3": 2, "xe-0/1/0": 3, "xe-1/0/3": 4, "xe-1/0/0": 5, "ge-6/2/0": 6, "xe-0/1/1": 7, "ge-6/0/0": 8}
    newy32aoa = {"xe-0/0/0": 2, "xe-0/1/3": 3, "et-3/0/0-0": 4, "et-3/0/0-1": 5}
    hous = {"xe-0/0/0": 2, "xe-1/0/0": 3, "xe-1/1/0": 4, "xe-3/1/0": 11, "xe-0/1/0": 7}
    salt = {"ge-6/0/0": 2, "ge-6/1/0": 3, "xe-0/1/1": 4, "xe-0/1/3": 5, "xe-0/0/1": 6, "xe-0/1/0": 7}
    wash = {"xe-6/3/0": 2, "xe-0/1/3": 3, "et-3/0/0-0": 4, "et-3/0/0-1": 5, "xe-0/0/0": 6, "xe-0/0/3": 7, "xe-1/1/3": 8}
    seat = {"xe-0/0/0": 2, "xe-1/0/0": 3, "xe-0/1/0": 4, "xe-2/1/0": 5}
    port_dict = {"atla": atla, "chic": chic, "losa": losa, "kans": kans, "newy32aoa": newy32aoa, "hous": hous,
                 "salt": salt, "wash": wash, "seat": seat}
    for d in device:
        for line in open(d + "ap.txt", "r"):
            rule = line.split()
            # ['fw', '69274112', '24', 'xe-0/0/1.110']
            dst = rule[1] + '/' + rule[2]
            out_port = rule[3].split(".")
            try:
                out_port = port_dict[d][out_port[0]]
                if out_port==11:
                    add_flow(devive_to_dpid[d], dst, 5)
                    add_flow(devive_to_dpid[d], dst, 6)
            except Exception as e:
                continue
            add_flow(devive_to_dpid[d], dst, out_port)
if __name__ == '__main__':
    install_path()

