# **Minimem - 32bit C# Based Memory Library**
## Basic Features:
1. Generic Read and Write methods for all standard types such as **float**, **int**, etc..
2. Pattern Scanner **(Ported from x64dbg)**
3. List Item 3
4. List Item 4

# **Known Issues/Bugs**
```cs
public static void StartFreezer()
public static void StopFreezer()
public static void AddFreezeValue(long address, string identifier, string valuetype, object value)
public static async Task RemoveFreezeValue(string identifier, int maxRetries = 5)
```
* **The above mentioned functions are generally not very stable (read: not threadsafe) and are recommended to not be used. I wont provide any example snippets for this as I would rather suggest you create your own method for "Freezing" a value (Like you do with CE). Will remove this on next push**


```cs
public static T ReadMultiLevelPointer<T>(long baseAddress, params int[] offsets) 
public static void WriteMultiLevelPointer<T>(long baseAddress, object value, params int[] offsets)
```
* I guess this is not really an Issue but we can pretend it is just to clarify something early on. The above mentioned functions are meant to Read and Write actual pointers, and will for each step in in the process **READ** the value of the baseAddress + offsets[stepIdx]. Meaning, if you have base address and offsets that are basically only supposed to be added onto the base address directly, and then read the value. This is not the functions you are looking for.


* Error handling in most cases just consist of try catch statements unfortunately, not really an issue per say but just letting you know

* There are probably quite many other bugs I have not yet encountered, but dont be suprised if you encounter anything that is not mentioned in this list.


# **How to get started**
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

A deeper explanation on how to use the above mentioned method can be found under section **Examples/Usage**, subsection **Example 10**.

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

## **Example 7: Closing an internally opened handle by the remote process, by its handle type and handle name**
### **Signatures**
```cs
public static bool TryFindDeleteHandle(string strHandleType, string strHandleName)
```

## **Usage Example: TryFindDeleteHandle**
```cs
// Lets assume here the process you're attached too spawns a Mutex on startup, that prevents you from
// launching another instance of the process

// Note, the handle name and its type can be seen by doing the following,
// Opening Process Hacker -> Selecting the process -> Highlighting selected process and right clicking going into Properties -> Finding the handle in the 'Handles' tab

// For this example were going to assume the handle we want to close is of "Mutant" type, and is named "WindowMutex";
string strOurHandleType = "Mutant";
string strOurHandleName = "WindowMutex";

if (Mem.TryFindDeleteHandle(strOurHandleType, strOurHandleName)) {
    // We successfully found the handle we wanted
    // and the function have closed that handle

    // In theory, you should be able to launch another instance of said process etc
} else {
    // We failed to close the handle
    // Could be because of many reasons
    // Some are

    /*
    * 1. Handle with type and name does not exist
    * 2. Insufficient priviliges (try restarting the program as administrator)
    * 3. Internal measures to prevent an external process from closing any handles
    */

    //  Again,
    // https://www.pinvoke.net/default.aspx/kernel32.getlasterror
    // Where are you when we need you???
}
```

# Notes regarding the internal code for function 'TryFindDeleteHandle(string, string)'
It really is an abomination, and I dont suggest looking up what is going on behind the scenes.
If anyone wants to improve this and send a PR feel free to do so.

## **Example 8: Logging**
### **Signatures**
```cs
public static void Log(string message,MessageType messageType = MessageType.INFO, bool writeToDebug = true, bool writeToFile = false)
```

## **Usage Example: Log**
```cs
// The other optional parameters, namely 
/*
* writeToDebug
* writeToFile
*/
// Dont need to much of an explanation I think

Mem.Log("We logged something with MessageType set to DEFAULT", MessageType.DEFAULT);
Mem.Log("We logged something with MessageType set to INFO", MessageType.INFO);
Mem.Log("We logged something else with MessageType set to WARNING", MessageType.WARNING);
Mem.Log("We logged something else with MessageType set to ERROR", MessageType.ERROR);
```

## **Result**
![alt text](https://i.imgur.com/XU6yKTC.png "Results")


## **Example 9: FASM dotNet related functionality**
## Link to repository: [ZenLulz/Fasm.NET](https://github.com/ZenLulz/Fasm.NET) (Please read this for how to use these)
## Link to Flat Assembler Manual: [Flat Assembler User Manual](https://flatassembler.net/docs.php?article=fasmg_manual) (Good information for syntax help)

Basically, the functions here are "wrappers" to the functions available in **FASM.Net.dll**
### **Signatures**
```cs
public static byte[] Assemble(string mnemonics)
public static byte[] Assemble(string[] mnemonics)
public static bool TryAssemble(string[] mnemonics, out byte[] assembled)
```

## **Usage Example: TryAssemble**
```cs
string[] ourMnemonics = new string[] {
    "use32", // Basically justy signifies our defined assembly code down below is 32bit
    "xor eax,eax", // Basically clear the contents of eax
    "retn", // return instruction mnemonic
};

if (Mem.TryAssemble(ourMnemonics, out byte[] mnemonicsAsBytes)) {
    // FASM.Net successfully translated our mnemonics into actual shellcode
    // the generated shellcode is inside byte array 'mnemonicsAsBytes'

    // Proceed to do whatever you need with the shellcode
    // Maybe inject it into the process (Example code of how to inject shellcode is available if you scroll down)
} else {
    // Something went wrong
    // No real error to know what exactly went wrong
    // If you want to get more specific errors thrown with information you can use the following snippet
}
```

## **Sub Example: Assemble (throws FASMNetAssmblerException)**
```cs
string[] ourMnemonics = new string[] {
    "use32", // Basically justy signifies our defined assembly code down below is 32bit
    "clear eax", // Invalid instruction
    "return", // Invalid instruction
};

byte[] ourMnemonicsAsBytes = Mem.Assemble(ourMnemonics);
// This will throw an exception with the index of the invalid instruction, and a more indepth explanation on what went wrong
```

## My recommendation is to use Mem.Assemble(string[]) when assembling and adding your own error handling
## I only use Mem.TryAssemble(string[], out byte[]) where I know I have provided valid 32bit assembly mnemonics

## **Example 10: Detouring/Trampolining executable code with support for callback when code is called**
Make sure to strap yourself to your chair as the function here is quite messy **BUT VERY USEFUL**  if you know how to use it properly
### **Signatures**
```cs
public static bool CreateTrampolineAndCallback(
    IntPtr targetAddress, 
    int targetAddressInstructionCount, 
    string[] mnemonics, 
    CallbackDelegate codeExecutedEventDelegate, 
    out CallbackObject createdObject, 
    string identifier = "", 
    bool shouldSuspend = true, 
    bool preserveOriginalInstruction = false, 
    bool implementCallback = true, bool 
    implementRegisterDump = true
)
```

## **Example usage: CreateTrampolineAndCallback(params...) to dump all 32bit registers at instruction in remote process**
```cs
using System;
using static MiniMem.Constants;
using Mem = MiniMem.MiniMem;

namespace Test
{
	class Program
	{
                // You dont need to define the structure, as its already defined within the Library
                // This is just for better visualizing what happens 
                [StructLayout(LayoutKind.Sequential)]
		public struct Registers
		{
			public int EAX; // 0x0
			public int EBX; // 0x4
			public int ECX; // 0x8
			public int EDX; // 0x12
			public int EDI; // 0x16
			public int ESI; // 0x20
			public int EBP; // 0x24
			public int ESP; // 0x28
		}
        
                // You dont need to define the structure, as its already defined within the Library
                // This is just for better visualizing what happens 
                public class CallbackObject
		{
			public IntPtr ptr_HitCounter = IntPtr.Zero;
			public TrampolineInstance class_TrampolineInfo;
			public string str_CallbackIdentifier = "";

			public uint LastValue = 0;
			public CallbackDelegate ObjectCallback;
		}

                // You dont need to define the structure, as its already defined within the Library
                // This is just for better visualizing what happens 
                public class TrampolineInstance
		{
			public RemoteAllocatedMemory AllocatedMemory;

			public string Identifier = "";

			public long TrampolineOrigin = -1;
			public long TrampolineDestination = -1;

			public IntPtr optionalHitCounterPointer = IntPtr.Zero;
			public IntPtr optionalRegisterStructPointer = IntPtr.Zero;

			public long TrampolineJmpOutAddress = -1;
			public long TrampolineJmpOutDestination = -1;
			public byte[] OriginalBytes = null;
			public byte[] NewBytes = null;

			public bool SuspendNeeded = false;

			public void Restore()
			{
				MiniMem.WriteBytes(TrampolineOrigin, OriginalBytes);
				AllocatedMemory.Free();	
			}
		}


		[STAThread]
		static void Main(string[] args)
		{
			if (!Mem.Attach("game.bin"))
			{
				Environment.Exit(-1);
			}

			CallbackObject obj; // The returned object from function CreateTrampolineAndCallback will be stored in this
			CallbackDelegate CodeExecutedEvent = MyCallbackEvent; // Expects a delegate with signature void(object)

                        // Information on how FindProcessModule and FindPatternSingle works and what it returns can be found if you scroll up
			IntPtr addr = Mem.FindPatternSingle(Mem.FindProcessModule("target_module", false), "33 FF 39 78 08 0F 8E ?? ?? ?? ?? 8B CE E8 ?? ?? ?? ?? 84 C0");
			if (addr == IntPtr.Zero) return; // Always good to check for this before actually attempting to do anything else

			bool result = Mem.CreateTrampolineAndCallback(
				addr, // Target Address,
				5, // targetAddressInstructionCount
				new string [] // Mnemonics to be injected into our code cave (the trampoline will jump to this code cave and execute this code)
				{
					// Feel free to add any custom mnemonics you might need, but if you only look to dump register values at a certain instruction you can pass an empty string[]
                                        // like I do here

					// here will our register dump mnemonic be placed is ImplementRegisterDump is true
					// Here will the inc instruction will be placed in our case if ImplementCallback is true
					// Here will the jump back out to ('addr' + 5 bytes) be placed
				},
				CodeExecutedEvent, // codeExecutedEventDelegate (Points to our method below called 'MyCallbackEvent')
				out  obj,// Created Callback Object
				"whatever identifier you want to give this trampoline",
				true, // ShouldSuspend
				true, // PreserveOriginalInstruction
				true, // ImplementCallback
				true // ImplementRegisterDump
			);

			if (obj != null && result) // If the returned object is not null and our function succeeded
			{
				Mem.ActiveCallbacks.Add(obj); // Add the newly created object to the Callback monitor thread

				Console.ReadLine(); // Basically keep the program running until the user presses any key
				Mem.Detach(); // When any key is pressed, detach will as the name says Detach from the remote process
                                // and Restore any applied Trampolines made 
			}
		}

		public static void MyCallbackEvent(object callbackObject)
		{
			if (callbackObject == null) return; // Always good to have a check for null
			CallbackObject obj = (CallbackObject)callbackObject; // Cast passed object into an actual CallbackObject type

                        Console.WriteLine($"Code injected for detour with identfier {obj.str_CallbackIdentifier} got executed once by the remote process!")
		}
	}
}
```

## **(somewhat) In depth Explanation about the different components of the process above**
Lets assume, you have found and instruction inside a remote process that is related to something of your interest
In this example, lets assume this instruction accesses the address to your players health

It might look like this.

![alt text](https://i.imgur.com/X7VbJnJ.png "Results")

We will place a detour at the instruction highlighted in green, to dump the value of EDI so we can read the value directly from our C# application
Select the instruction, and press Show dissasembler

Now we're here

![alt text](https://i.imgur.com/ZFAqsa9.png "Results")

Before moving down, we note down at what address the instruction is at.

**Limitation of jmp hooks: To place the jmp hook we need atleast 5 bytes, We see that the instruction highlighted in green is only 3 bytes, meaning we have to take 2 more bytes. For this we just take the direct next 2 bytes relative from our target instruction**

**The highlighted bytes here are the ones we will overwrite**

![alt text](https://i.imgur.com/6HLcR7W.png "Results")

**Explanation**

The bytes
```
8B 4F 08 50 51
```

will be overwritten and be
```
E9 <Address to code cave>
```

Please note that you can overwrite practically any amount of bytes, **the only limitation as said above is that there is atleast 5 bytes!**
Note down the amount of bytes we will overwrite (in our case here its 5 bytes)

Now to actually implementing the the detour and its callback, lets look at the function 'CreateTrampolineAndCallback' and its parameters

```cs
// etc
// some other code here

CallbackObject obj; // The returned object from function CreateTrampolineAndCallback will be stored in this
CallbackDelegate CodeExecutedEvent = MyCallbackEvent; // Expects a delegate with signature void(object)

IntPtr targetInstruction = new IntPtr(address to our target instruction); // Fill in this yourself

bool result = Mem.CreateTrampolineAndCallback(
    targetInstruction, // The target instruction start location where we will place our jmp

    5, // The amount of bytes we are going to overwrite, we determined that we would only need to overwrite 5 bytes

    new string [] // Mnemonics to be injected into our code cave (the trampoline will jump to this code cave and execute this code)
    {
        // Feel free to add any custom assembly mnemonics you might need, but if you only look to dump register values at a certain instruction you can pass an empty string[]
        // like I do here

        // here will our register dump mnemonic be placed is ImplementRegisterDump is true
        // Here will the inc instruction will be placed in our case if ImplementCallback is true
        // Here will the jump back out to ('addr' + 5 bytes) be placed
    },
    CodeExecutedEvent, // codeExecutedEventDelegate (Points to our method below called 'MyCallbackEvent')
    out  obj,// Created Callback Object

    "player_struct_detour", // You can name this detour anything you want
    // as we are kinda detouring and dumping the player structure, we can name it to something related to that 

    true, // This is mostly for not crashing when overwriting the original instruction, you can keep it set at true
    // Having it on true ensures that while we modify the code of the remote process (adding our detour), no other code wont be executed and the game wont (hopefully) crash

    true, // Having set this to true, will write the original overwritten instructions at the start of our code cave, in most cases you
    // can have this set to true, more info on when to set it to false can be found if you scroll down a bit

    true, // We want to implement a callback that notifies us when our injected code has been executed, so set parameter ImplementCallback to true
    true // We want to dump register values, so set parameter ImplementRegisterDump to true
);

// some other code here
// etc
```

The code here is basically exactly what we need to successfully implement a detour and its callback. We will now proceed to call it it, here is a full example of code how we will go about

```cs
using System;
using static MiniMem.Constants;
using Mem = MiniMem.MiniMem;

namespace Test
{
	class Program
	{
                // You dont need to define the structure, as its already defined within the Library
                // This is just for better visualizing what happens 
                [StructLayout(LayoutKind.Sequential)]
		public struct Registers
		{
			public int EAX; // 0x0
			public int EBX; // 0x4
			public int ECX; // 0x8
			public int EDX; // 0x12
			public int EDI; // 0x16
			public int ESI; // 0x20
			public int EBP; // 0x24
			public int ESP; // 0x28
		}
        
                // You dont need to define the structure, as its already defined within the Library
                // This is just for better visualizing what happens 
                public class CallbackObject
		{
			public IntPtr ptr_HitCounter = IntPtr.Zero;
			public TrampolineInstance class_TrampolineInfo;
			public string str_CallbackIdentifier = "";

			public uint LastValue = 0;
			public CallbackDelegate ObjectCallback;
		}

                // You dont need to define the structure, as its already defined within the Library
                // This is just for better visualizing what happens 
                public class TrampolineInstance
		{
			public RemoteAllocatedMemory AllocatedMemory;

			public string Identifier = "";

			public long TrampolineOrigin = -1;
			public long TrampolineDestination = -1;

			public IntPtr optionalHitCounterPointer = IntPtr.Zero;
			public IntPtr optionalRegisterStructPointer = IntPtr.Zero;

			public long TrampolineJmpOutAddress = -1;
			public long TrampolineJmpOutDestination = -1;
			public byte[] OriginalBytes = null;
			public byte[] NewBytes = null;

			public bool SuspendNeeded = false;

			public void Restore()
			{
				MiniMem.WriteBytes(TrampolineOrigin, OriginalBytes);
				AllocatedMemory.Free();	
			}
		}


		[STAThread]
		static void Main(string[] args)
		{
			if (!Mem.Attach("game.bin"))
			{
				Environment.Exit(-1);
			}

			CallbackObject obj; // The returned object from function CreateTrampolineAndCallback will be stored in this
			CallbackDelegate CodeExecutedEvent = MyCallbackEvent; // Expects a delegate with signature void(object)

                        IntPtr targetInstruction = new IntPtr(address to our target instruction); // Fill in this yourself

                        bool result = Mem.CreateTrampolineAndCallback(
                            targetInstruction, // The target instruction start location where we will place our jmp

                            5, // The amount of bytes we are going to overwrite, we determined that we would only need to overwrite 5 bytes

                            new string [] // Mnemonics to be injected into our code cave (the trampoline will jump to this code cave and execute this code)
                            {
                                // Feel free to add any custom assembly mnemonics you might need, but if you only look to dump register values at a certain instruction you can pass an empty string[]
                                // like I do here

                                // here will our register dump mnemonic be placed is ImplementRegisterDump is true
                                // Here will the inc instruction will be placed in our case if ImplementCallback is true
                                // Here will the jump back out to ('addr' + 5 bytes) be placed
                            },
                            CodeExecutedEvent, // codeExecutedEventDelegate (Points to our method below called 'MyCallbackEvent')
                            out  obj,// Created Callback Object

                            "player_struct_detour", // You can name this detour anything you want
                            // as we are kinda detouring and dumping the player structure, we can name it to something related to that 

                            true, // This is mostly for not crashing when overwriting the original instruction, you can keep it set at true
                            // Having it on true ensures that while we modify the code of the remote process (adding our detour), no other code wont be executed and the game wont (hopefully) crash

                            true, // Having set this to true, will write the original overwritten instructions at the start of our code cave, in most cases you
                            // can have this set to true, more info on when to set it to false can be found if you scroll down a bit

                            true, // We want to implement a callback that notifies us when our injected code has been executed, so set parameter ImplementCallback to true
                            true // We want to dump register values, so set parameter ImplementRegisterDump to true
                        );

			if (obj != null && result) // If the returned object is not null and our function succeeded
			{
				Mem.ActiveCallbacks.Add(obj); // Add the newly created object to the Callback monitor thread

				Console.ReadLine(); // Basically keep the program running until the user presses any key
				Mem.Detach(); // When any key is pressed, detach will as the name says Detach from the remote process
                                // and Restore any applied Trampolines made 
			} else 
                        {
                            // Something went wrong with adding our callback
                        }
		}

		public static void MyCallbackEvent(object callbackObject)
		{
			if (callbackObject == null) return; // Always good to have a check for null
			CallbackObject obj = (CallbackObject)callbackObject; // Cast passed object into an actual CallbackObject type
                        // Now we said that we knew our structure of interest was stored in register EDI;
                        // Lets proceed to read the contents of EDI

                        Registers register_Struct = Mem.ReadMemory<Registers>(obj.class_TrampolineInfo.optionalRegisterStructPointer.ToInt64());

                        string strPlayerStructureBaseAddress = $"0x{register_Struct.EDI:X}";
                        string strPlayerHealthAddress = $"0x{register_Struct.EDI+8:X}";

                        Console.WriteLine(strPlayerStructureBaseAddress); // print this to the console
		}
	}
}
```

And this is the final output

![alt text](https://i.imgur.com/NoUbuxi.png "Results")