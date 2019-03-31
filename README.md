# Minimem - 32bit C# Based Memory Library
## Basic Features:
1. Generic Read and Write methods for all standard types such as **float**, **int**, etc..
2. List Item 2
3. List Item 3
4. List Item 4

## How to get started:
1. Make sure to reference both **minimem.dll** and **FASM.Net.dll** in your application.
2. Add these usings to the top of your document

```cs
using static MiniMem.Constants;
using Mem = MiniMem.MiniMem;
```

3. To attach/get a Read/Write handle to a remote process you call it like this

```cs
if (!Mem.Attach("your process name")) {
    Environment.Exit(-1); // <-- This will only be executed if it for some reason fails to attach to your process
}

// We attached succesfully to your process, you can proceed to read write here
```

