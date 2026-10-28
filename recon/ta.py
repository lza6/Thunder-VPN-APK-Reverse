import frida, sys
d=frida.get_usb_device(timeout=10)
print("device:", d, d.type)
try:
    print("params:", d.query_system_parameters())
except Exception as e:
    print("params err", e)
s=d.attach("Thunder VPN")
print("attached:", s)
sc=s.create_script("send({a:Process.arch, p:Process.id, m:Process.enumerateModules().slice(0,5).map(x=>x.name)})")
sc.on("message", lambda m,data: print("MSG:", m))
sc.load()
import time; time.sleep(2)
