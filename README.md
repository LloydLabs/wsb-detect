# ⏳ wsb-detect
wsb-detect enables you to detect if you are running in Windows Sandbox ("WSB"). The sandbox is used by Windows Defender for dynamic analysis, and commonly manually by security analysts and alike. At the tail end of 2019, Microsoft introduced a new feature named Windows Sandbox (WSB for short). The techniques used to fingerprint WSB are outlined below, in the techniques section. Feel free to submit a pull request if you have any fingerprinting ideas 🎉. I've been messing around with it now and then, I will have more on Windows Sandbox coming soon.

Windows Sandbox allows you to quickly, within 15s, create a disposable Hyper-V based Virtual Machine with all of the qualities a familiar VM would have such as clipboard sharing, mapping directories etc. The sandbox is also the underlay for Microsoft Defender Application Guard (WDAG), for dynamic analysis on Hyper-V enabled hosts and can be enabled on any Windows 10 Pro or Enterprise machine. It's not particularly interesting, but nonetheless could prove useful in implant development. Thank you to my friend [Jonas L](https://twitter.com/jonasLyk) for guidance when I was exploring the sandbox internals (more to come on this).

# Usage
The `detect.h` header exports all of the functions which can be combined to detect if

```c
#include <stdio.h>
#include "detect.h"

int main(int argc, char** argv)
{
  // example vmsmb & username check
  if (wsb_detect_dev() || wsb_detect_username())
  {
    puts("We're in Windows Sandbox!");
    return 0;
  }
  
  return 1;
}
```

# Techniques
### `wsb_detect_proc`
Checks for `CExecSvc.exe`, which is the container execution service, handling a lot of the heavy lifting internally.

### `wsb_detect_time`
The image for the sandbox seems to be built on `Saturday, ‎December ‎7, ‎2019, ‏‎9:14:52 AM` - this is around the time Windows Sandbox was released to the public. This check cross references the creation timestamp on the `mountmgr` driver.

### `wsb_detect_username`
This method will check if the current username is `WDAGUtilityUserAccount`, the account used by default in the sandbox.

### `wsb_detect_suffix`
This method will use `GetAdaptersAddresses`, walk over the list of adapters, and compare the DNS suffix to `mshome.net` - which is used by default in the sandbox.

### `wsb_detect_dev`
Checks if the raw device `\\.\GLOBALROOT\device\vmsmb` can be opened, which is used for communication with the host over SMB.

### `wsb_detect_cmd`
On startup, search under the `RunOnce` key in `HKEY_LOCAL_MACHINE` for a command which sets the password never to expire.

### `wsb_detect_genuine`
A more generic method when it comes to sandbox detection, however from tests the Windows doesn't seem to be verified as legitimate in the VMs

# Trivia
If you wish to contact me quicker, feel free to contact me on [Twitter](https://twitter.com/LloydLabs) or [e-mail](mailto:me@syscall.party). Also, it's possible on the host to detect if the sandbox is running, by checking if you can create a mutex named  `WindowsSandboxMutex`. This limits the sandbox to one virtual-machine per host, however, you can release this mutex by simply duplicating the handle and calling `ReleaseMutex` - viola, you can have multiple instances.

![mutex check in latest build at 0x140021F1C](https://i.imgur.com/XWupOpm.png)
