using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;
using System.Threading;
using static MiniMem.Constants;
using static MiniMem.MiniMem;

namespace MiniMem
{
	public class Freezer
	{
		public static bool flagTerminateThread = false;
		public static bool flagThreadIsRunning = false;
		public static List<FreezeItem> FreezeCollection = new List<FreezeItem>();

		public static void FreezeLoop()
		{
			flagThreadIsRunning = true;
			Debug.WriteLine("FreezeThread has been started!");

			while (!flagTerminateThread)
			{
				foreach (FreezeItem item in FreezeCollection)
				{
					if (!item.IsValid()) continue;
					if (AttachedProcess.IsAttached()) continue;

					switch (item.ValueType)
					{
						case "float":
							WriteMemory<float>(item.Address, item.Value);
							break;
						case "int":
							WriteMemory<int>(item.Address, item.Value);
							break;
						case "string":
							WriteString(item.Address, Convert.ToString(item.Value), Encoding.UTF8);
							break;
						case "uint":
							WriteMemory<uint>(item.Address, item.Value);
							break;
						case "bytes":
						case "byte":
							WriteBytes(item.Address, (byte[]) item.Value);
							break;
						case null:
							throw new ArgumentException("Value type was not set! (NULL)");
						default:
							throw new ArgumentException("Encountered unknown value type '" + item.ValueType + "'");

					}
				}

				Thread.Sleep(10);
			}

			Debug.WriteLine("FreezeThread has exited!");
			flagTerminateThread = false;
			flagThreadIsRunning = false;
		}
	}
}
