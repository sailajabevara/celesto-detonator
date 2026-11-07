# Runs INSIDE the guest as sitecustomize.py (PYTHONPATH=/opt/audit). Records what an installing
# package touches using Python audit hooks. Writes via a pre-opened fd to avoid recursion.
import sys, os, json, time

_p = os.environ.get("AUDIT_LOG")
if _p:
    _fd = os.open(_p, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o666)
    _busy = False
    _n = 0
    _WFLAGS = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_APPEND | os.O_TRUNC
    _SKIP_READ = ("/usr/lib/python", "/usr/local/lib/python", "/proc/", "/sys/", "/dev/", "/lib/",
                  "/usr/lib/", "/usr/share/zoneinfo", "/opt/audit")
    _EV = {"open", "socket.connect", "socket.getaddrinfo", "urllib.Request", "subprocess.Popen",
           "os.system", "os.exec", "os.posix_spawn", "os.remove", "os.rename", "os.rmdir",
           "shutil.rmtree", "ctypes.dlopen"}

    def _hook(ev, args):
        global _busy, _n
        if _busy or ev not in _EV or _n > 20000:
            return
        _busy = True
        try:
            rec = {"t": round(time.time(), 3), "pid": os.getpid(), "ev": ev}
            if ev == "open":
                path = args[0]
                if not isinstance(path, (str, bytes)):
                    return
                path = os.fsdecode(path)
                flags = args[2] if isinstance(args[2], int) else 0
                write = bool(flags & _WFLAGS)
                if path.endswith(".pyc"):
                    return
                if not write and path.startswith(_SKIP_READ):
                    return
                rec["path"] = path[:300]
                rec["write"] = write
            elif ev == "socket.connect":
                rec["addr"] = repr(args[1])[:120]
            elif ev == "socket.getaddrinfo":
                rec["host"] = repr(args[0])[:120]
            elif ev == "urllib.Request":
                rec["url"] = str(args[0])[:400]
            elif ev in ("subprocess.Popen", "os.exec", "os.posix_spawn"):
                a = args[1] if len(args) > 1 else args[0]
                a = a if isinstance(a, (list, tuple)) else [a]
                rec["argv"] = [str(x)[:200] for x in a][:12]
            elif ev == "os.system":
                rec["argv"] = [str(args[0])[:300]]
            elif ev in ("os.remove", "os.rename", "os.rmdir", "shutil.rmtree"):
                rec["path"] = str(args[0])[:300]
            elif ev == "ctypes.dlopen":
                rec["path"] = str(args[0])[:200]
            _n += 1
            os.write(_fd, (json.dumps(rec) + "\n").encode())
        except Exception:
            pass
        finally:
            _busy = False

    sys.addaudithook(_hook)
