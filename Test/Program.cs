using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Threading;
using static MiniMem.Constants;
using MiniMem;
using static MiniMem.Helper;
using Mem = MiniMem.MiniMem;
using System.Windows.Forms;

namespace Test
{
	class Program
	{
		[STAThread]
		static void Main(string[] args)
		{
			if (!Mem.Attach("game.bin"))
			{
				Environment.Exit(-1);
			}

			CallbackObject obj;
			CallbackDelegate CodeExecutedEvent = MyCallbackEvent;

			bool result = Mem.CreateTrampolineAndCallback(
				new IntPtr(0x02B28E54), // Target Address,
				5, // targetAddressInstructionCount
				new[] // Mnemonics to be injected
				{
					"use32",
					"push 00",
					"push 01",
					"call ecx",
					// here will our register dump mnemonic be placed is ImplementRegisterDump is true
					// Here will the inc instruction will be placed in our case if ImplementCallback is true
					// Here will the jump back out to (Target Address + 5) be placed
				},
				CodeExecutedEvent, // codeExecutedEventDelegate
				out  obj,// Created Callback Object
				"MY_IDENTIFIER",
				true, // ShouldSuspend
				false, // PreserveOriginalInstruction
				true, // ImplementCallback
				true // ImplementRegisterDump
			);

			if (obj != null && result)
			{
				Mem.ActiveCallbacks.Add(obj);

				while (true)
				{
					
					Thread.Sleep(1);
				}
			}

			

			
			int z = 1;
			/*
			Thread t = new Thread(CallbackLoop);
			t.Start();

			Thread s = new Thread(HackLoop);
			s.Start();


			//InstallCharacterWndHook();
			//InstallFishingWndHook();

			Console.WriteLine("Enter anything to remove all hooks:");
			Console.Title = "Enter anything and press enter to remove all hooks";
			string resp = Console.ReadLine();

			if (!string.IsNullOrWhiteSpace(resp))
			{
				s.Abort();
				t.Abort();

				foreach (CallbackObject obj in Mem.ActiveCallbacks)
				{
					Mem.WriteBytes(obj.class_TrampolineInfo.TrampolineOrigin, obj.class_TrampolineInfo.OriginalBytes);
					Mem.FreeMemory(obj.class_TrampolineInfo.AllocatedMemory);
					Console.WriteLine("Restored stuff for object '" + obj.str_CallbackIdentifier + "'!");
				}
			}
			*/
		}

		
		public static void MyCallbackEvent(object callbackObject)
		{
			
			if (callbackObject == null) return;
			CallbackObject obj = (CallbackObject)callbackObject;
			
			Console.WriteLine($"Code cave at 0x{obj.class_TrampolineInfo.TrampolineDestination:X} was executed and our callback event was called!");
		}

	}
}
