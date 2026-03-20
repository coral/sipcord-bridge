# SIPcord Bridge

This is a slice of the code that powers [SIPcord](https://sipcord.net/) that you can use to self host something similar. It's not the full SIPcord package but rather the core functionality used in SIPcord with ways to build your own backend adapter. SIPcord itself uses this as a component of the full build so the code is the same that runs on the public bridges.

This means you have to build the call routing backend yourself. I am including a `static-router` backend which you can use to map extensions in a TOML file like this
```toml
[extensions]
1000 = { guild = 123456789012345620, channel = 987654321012345620 }
2000 = { guild = 123456789012345620, channel = 111222333444555620 }
```
but if you want more fancy routing you have to build it. You can easily use sipcord-bridge as a library and provide your own routers by implementing the `Backend` trait.

This was written a mix between myself and claude, sure, some of it's big slop but the parts I care about are not.

### Can you help me set this up?

**No.** I am not providing support for this as my goal is to run [sipcord.net](https://sipcord.net/), not support self hosting. If you want to run this self hosted, feel free to use this code but you are on your own here.

### I have a feature request!

**PR's welcome**. No really, feel free to implement it and contribute.

### Acknowledgements

- Thanks to [dusthillguy](https://www.youtube.com/watch?v=IK1ydvw3xkU) for letting me use the song *"Joona Kouvolalainen buttermilk"* as hold music and distribute it.
- Thanks to [wberg](https://wberg.com/) for hosting `bridge-eu1`
- Thanks to [chrischrome](https://litenet.tel/) for hosting `bridge-use1`

### License

Code is AGPLv3
Dusthillguy track is whatever dusthillguy wishe