TODO: refresh view when recv new change
function example like: 
    refresh_view()

Use udt to catch stack frame

```python
import idaapi

func_ea = 0x190442
tinfo = idaapi.tinfo_t()
idaapi.get_tinfo(tinfo, func_ea)

print(tinfo)
func_t = idaapi.func_t()
frame = tinfo.get_func_frame(func_t)
print(frame)
```