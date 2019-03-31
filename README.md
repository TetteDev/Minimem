# **Minimem - 32bit C# Based Memory Library**
## Basic Features:
1. Generic Read and Write methods for all standard types such as **float**, **int**, etc..
2. Pattern Scanner **(Ported from x64dbg)**
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

4. At this point, you're free to use all the functions inside the the Minimem library.

## **Notes: To detach from a process, and short explanation what the CallbackThread/ActiveCallbacks is/does**
If you have cloned the repository or checking the code from the github page, you might see that upon calling the **Attach(string)** function, you have probably seen that
it also launches a thread that runs in the background. In most cases you can probably ignore this as unless you use function

```cs
public static bool CreateTrampolineAndCallback(IntPtr targetAddress, int targetAddressInstructionCount, string[] mnemonics, CallbackDelegate codeExecutedEventDelegate, out CallbackObject createdObject, string identifier = "", bool shouldSuspend = true, bool preserveOriginalInstruction = false, bool implementCallback = true, bool implementRegisterDump = true)
```

A deeper explanation on how to use the above mentioned method can be found under section **Examples/Usage**.

*PLACEHOLDER TEXT (Will update this section later): Lorem ipsum dolor sit amet, consectetur adipiscing elit. Aenean aliquam lectus felis, et porta urna vestibulum vel. Sed finibus pellentesque nisi, finibus dapibus sem consectetur eget. Vivamus at viverra massa. Sed facilisis at enim non finibus. Aenean quis enim a mauris sollicitudin fringilla non ac nulla. Maecenas gravida sem eros, eget accumsan odio cursus vitae. Mauris sollicitudin diam ultricies, tincidunt dui eget, porttitor tortor. Nam ut diam arcu. Nam at porta velit, vitae ornare urna.*


# **Examples/Usage**
* **Reading/Writing**
```cs
public static T ReadMemory<T>(long address) where T : struct
public static void WriteMemory<T>(long address, object value) where T : struct
```

## **Example 1: Reading an Integer from an address**
```cs
long intPlayerHealthAddress = 0x12345678; // Our address that we want to read from
int intPlayerHealthValue = Mem.ReadMemory<int>(intPlayerHealthAddress);

Console.WriteLine($"Player Health: {intPlayerHealthValue}"); // Assuming 'intPlayerHealthAddress' in this case was a valid address, this would print the read integer value read from that address
```

## **Example 2: Writing an Integer from to an adddress**
```cs
long intPlayerHealthAddress = 0x12345678; // Our address that we want to read from
int intDesiredNewHealthValue = 999; // Whatever value we want to write to the address stored in variable 'intPlayerHealthAddress'

Mem.WriteMemory<int>(intPlayerHealthAddress, intDesiredNewHealthValue); // Perform the actual write to the desired address
```

**Please note that you are not limited to reading/writing only integer types (For strings and byte arrays, look at Example 3)**
```cs
float floatRead = Mem.ReadMemory<float>(0xFFFFFFF); // Reads a 'float' type
uint uintRead = Mem.ReadMemory<uint>(0xFFFFFFF); // Reads an 'uint' type

// Etc
```

## **Example 3: Reading/Writing strings and byte arrays**
### **ReadString Signature**
```cs
public static string ReadString(long address, Encoding defaultEncoding = default(Encoding), int maxLength = 256, bool zeroTerminated = false)
```

### **ReadBytes Signature**
```cs
public static byte[] ReadBytes(long address, int byteCount)
```

## **Usage Example - Strings**
```cs
long strPlayerNameAddress = 0x1234567; // Location where a certain string is located in memory you want to read
string strReadPlayerName = Mem.ReadString(strPlayerNameAddress); // Adjust the optional parameters of 'ReadString' method according to your needs if needed

Console.WriteLine($"Player Name: {strReadPlayerName}"); // Prints the read string to the console
```

## **Usage Example - Byte Arrays**
```cs
long anyLocationInMemory = 0x1234567; // Whatever location in memory you want to read from
int intAmountBytesToRead = 12; // The amount of bytes to read

byte[] readBytes = Mem.ReadBytes(anyLocationInMemory, intAmountBytesToRead); // Reads 'intAmountBytesToRead' amount of bytes from address stored in variable 'anyLocationInMemory'
// 'readBytes' now contain 12 bytes that have been read from the address in variable 'anyLocationInMemory'
```

## **Example 4: Pattern Scanner**
### **FindPatternSingle Signatures**
```cs
public static IntPtr FindPatternSingle(byte[] buffer, string pattern, int refBufferStartAddress = 0)
public static IntPtr FindPatternSingle(ProcModule processModule, string pattern, bool resultAbsolute = true)
public static IntPtr FindPatternSingle(long startAddress, long endAddress, string pattern, bool resultAbsolute = true)
```

## **Usage Example: Performing a pattern scan on a specific module**
```cs
// There are, as seen from the signatures above, 3 ways to perform a pattern scan on a specific memory region
// * Assuming you dont know a specific modules starting and ending address, you can fetch those values with the method
// Mem.FindProcessModule(string processname), which returns a ProcModule object

// Example using FindProcessModule and FindPatternSingle
ProcModule moduleInfo = Mem.FindProcessModule("module_name");
// Keep in mind Mem.FindProcessModule(string) returns NULL if it cannot find the desired process module, 
// so make sure to check for tht in your code before attempting to use the ProcModule object

/* SUPPORTED PATTERN TYPES
* 1. "90 90 ?? 90 90 90 ?? 90 90 90 90 ?? 90"
* 2. "90 ?0 ?? 90 9? 90 ?? ?? 90 90 ?0 ?9 90"
* 
* These are just example patterns, but show what types of wildcards are considered 'valid'
*/

string strPattern = "33 FF 39 78 08 0F 8E ?? ?? ?? ?? 8B CE E8 ?? ?? ?? ?? 84 C0"; // An example 'valid' pattern
IntPtr addressFound = Mem.FindPatternSingle(moduleInfo, strPattern);
if (addressFound != IntPtr.Zero) {
    // An address was found for the pattern provided inside the module 'module_name'
    // Do something here
} else {
    // The provided pattern did not yield any result from inside the module 'module_name'
    // Do something else here
}

// If your pattern was unique enough, variable 'addressFound' should contain the location of the first instance of the sequence of bytes provided
// in variable 'strPattern'.

// NOTE: If you provide a pattern that is not unique so to speak, function FindPatternSingle(ProcModule, string) will ALWAYS only return the first instance of those bytes
// What I recommend in this case: Improve your pattern so it is unique to exactly locate the specific instruction/function you want.
```

## Optional parameters *refBufferStartAddress* and *resultAbsolute* ##
*PLACEHOLDER TEXT (Will update this section later): Lorem ipsum dolor sit amet, consectetur adipiscing elit. Aenean aliquam lectus felis, et porta urna vestibulum vel. Sed finibus pellentesque nisi, finibus dapibus sem consectetur eget. Vivamus at viverra massa. Sed facilisis at enim non finibus. Aenean quis enim a mauris sollicitudin fringilla non ac nulla. Maecenas gravida sem eros, eget accumsan odio cursus vitae. Mauris sollicitudin diam ultricies, tincidunt dui eget, porttitor tortor. Nam ut diam arcu. Nam at porta velit, vitae ornare urna.*

## **Example 5: Suspending/Resuming Process**
### **Suspending/Resuming Signatures**
```cs
public static void SuspendProcess()
public static void ResumeProcess()
```

Pretty straight forward here, 
Use 'Mem.SuspendProcess()' to set the attached process in a suspended state and 'Mem.ResumeProcess()' to resume a process that has been set in a suspended state.
Dont think it needs to much explanation.

**Uses 
[PInvoke - SuspendThread](https://www.pinvoke.net/default.aspx/kernel32.suspendthread) and [PInvoke - ResumeThread](https://www.pinvoke.net/default.aspx/kernel32.resumethread) respectively**

## **Example 6: Allocating/Freeing memory inside a remote process**
### **Signatures**
```cs
// Allocating Memory
public static IntPtr AllocateMemory(uint size, uint protectionFlags, uint allocationFlags)
public static RemoteAllocatedMemory AllocateMemory(int size, MemoryProtection protectionFlags, AllocationType allocationFlags)

// Freeing Memory
public static bool FreeMemory(RemoteAllocatedMemory memoryItem)
public static void FreeMemory(IntPtr lpBase, int size)
```

**Uses 
[PInvoke - VirtualAllocEx](https://www.pinvoke.net/default.aspx/kernel32.virtualallocex) to allocate memory and [PInvoke - VirtualFreeEx](https://www.pinvoke.net/default.aspx/kernel32/VirtualFreeEx.html) respectively**

## **Usage Example: Allocating/Freeing memory**
```cs
// This example shows how to allocate/free memory using the following functions (namely the ones using RemoteAllocatedMemory object)
// public static RemoteAllocatedMemory AllocateMemory(int size, MemoryProtection protectionFlags, AllocationType allocationFlags)
// public static bool FreeMemory(RemoteAllocatedMemory memoryItem)

// EXAMPLE 1: Allocating memory

uint uintSizeToAllocate = 4; // 4byte section
RemoteAllocatedMemory someMemory = Mem.AllocateMemory(uintSizeToAllocate); // Proceed to try and allocate 4 bytes at the first best location inside our remote process
if (someMemory.Pointer != IntPtr.Zero) {
    // We successfully allocated 4 bytes of memory
    // and the location of that allocation is stored in 'someMemory.Pointer'

    // Proceed to do whatever you need to do
} else {
    // We failed to allocate 4 bytes into our remote process

    // NOTE: I should probably implement the usage of
    // https://www.pinvoke.net/default.aspx/kernel32.getlasterror
}

// EXAMPLE 2: Freeing memory
// This example assumes we still have the object 'someMemory' from the previous example
bool boolFreeResult = Mem.FreeMemory(someMemory); // Pass our RemoteAllocatedMemory object into the function
if (boolFreeResult) {
    // We successfully 'released' the previously allocated memory
} else {
    // We failed to free the previously allocated memory
    
    // Again, probably would be good to make use for 
    // https://www.pinvoke.net/default.aspx/kernel32.getlasterror
    // to actually know what went wrong
}

```