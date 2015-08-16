using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using System.Runtime.ExceptionServices;
using System.Diagnostics;

namespace PointerHook {
	[Flags()]
	public enum AllocType : uint {
		Commit = 0x1000,
		Reserve = 0x2000,
		Reset = 0x80000,
		LargePages = 0x20000000,
		Physical = 0x400000,
		TopDown = 0x100000,
		WriteWatch = 0x200000
	}

	[Flags()]
	public enum MemProtection : uint {
		NoAccess = 0x01,
		ReadOnly = 0x02,
		ReadWrite = 0x04,
		WriteCopy = 0x08,
		Exec = 0x10,
		ExecRead = 0x20,
		ExecReadWrite = 0x40,
		ExecWriteCopy = 0x80,
		PageGuard = 0x100,
		NoCache = 0x200,
		WriteCombine = 0x400
	}

	[StructLayout(LayoutKind.Sequential)]
	public struct SysInfo {
		[MarshalAs(UnmanagedType.U2)]
		public short ProcessorArch;
		[MarshalAs(UnmanagedType.U2)]
		public short Reserved;
		[MarshalAs(UnmanagedType.U4)]
		public int PageSize;
		public uint MinAppAddr;
		public uint MaxAppAddr;
		[MarshalAs(UnmanagedType.U4)]
		public int ActiveProcessorMask;
		[MarshalAs(UnmanagedType.U4)]
		public int NumOfProcessors;
		[MarshalAs(UnmanagedType.U4)]
		public int ProcessorType;
		[MarshalAs(UnmanagedType.U4)]
		public int AllocationGranularity;
		[MarshalAs(UnmanagedType.U2)]
		public short ProcessorLevel;
		[MarshalAs(UnmanagedType.U2)]
		public short ProcessorRevision;
	}

	[StructLayout(LayoutKind.Sequential, Pack = 1)]
	unsafe struct EXCEPTION_RECORD {
		public uint ExceptionCode;
		public uint ExceptionFlags;
		public EXCEPTION_RECORD* ExceptionRecord;
		public IntPtr ExceptionAddress;
		public uint NumberParameters;
		public fixed int ExceptionInformation[15];

		public uint GetExceptionCode() {
			return (ExceptionCode << 1) >> 1;
		}

		public override string ToString() {
			StringBuilder SB = new StringBuilder();
			SB.AppendFormat("ExceptionCode: 0x{0:X}\n", ExceptionCode);
			SB.AppendFormat("ExceptionFlags: 0x{0:X}\n", ExceptionFlags);
			SB.AppendFormat("ExceptionRecord: 0x{0:X}\n", (int)ExceptionRecord);
			SB.AppendFormat("ExceptionAddress: 0x{0:X}\n", ExceptionAddress);
			SB.AppendFormat("NumberParameters: 0x{0:X}\n", NumberParameters);
			SB.AppendLine("ExceptionInfo:");
			fixed (int* ExInfo = ExceptionInformation) {
				IntPtr* Info = (IntPtr*)ExInfo;
				for (int i = 0; i < 15; i++)
					SB.AppendFormat(" {0}: 0x{1:X}\n", i, Info[i].ToInt64());
			}
			return SB.ToString();
		}
	}

	[StructLayout(LayoutKind.Sequential, Pack = 1)]
	unsafe struct CONTEXT {
		public uint R0;
		public uint R1;
		public uint R2;
		public uint R3;
		public uint R4;
		public uint R5;
		public uint R6;
		public uint R7;
		public uint R8;
		public uint R9;
		public uint R10;
		public uint R11;
		public uint R12;
	}


	[StructLayout(LayoutKind.Sequential, Pack = 1)]
	unsafe struct EXCEPTION_PTRS {
		public EXCEPTION_RECORD* ExceptionRecord;
		public CONTEXT* ContextRecord;
	}

	enum VHRet : uint {
		ContinueSearch = 0x0,
		ContinueExecution = 0xffffffff,
	}

	[UnmanagedFunctionPointer(CallingConvention.StdCall)]
	unsafe delegate VHRet VectoredHandlerFunc(EXCEPTION_PTRS* Ptrs);

	static unsafe class Native {
		[DllImport("kernel32", SetLastError = true, CallingConvention = CallingConvention.Winapi)]
		public static extern void GetSystemInfo(out SysInfo lpSystemInfo);

		[DllImport("kernel32", SetLastError = true, CallingConvention = CallingConvention.Winapi)]
		public static extern IntPtr VirtualAlloc(IntPtr Addr, uint Size, AllocType AType, MemProtection Protect);

		[DllImport("kernel32", SetLastError = true, CallingConvention = CallingConvention.Winapi)]
		public static extern bool VirtualProtect(IntPtr Addr, uint Size, MemProtection NewProtect, out MemProtection OldProtect);

		[DllImport("kernel32", SetLastError = true, CallingConvention = CallingConvention.Winapi)]
		public static extern IntPtr AddVectoredExceptionHandler(int First, VectoredHandlerFunc Handler);

		[DllImport("kernel32", SetLastError = true, CallingConvention = CallingConvention.Winapi)]
		public static extern void RaiseException(uint Code, uint Flags, uint NumOfArgs, int* Args);
	}

	unsafe class HackyPointer : IDisposable {
		IntPtr Pointer;
		uint Size;

		static uint PSize;
		public static uint PageSize {
			get {
				if (PSize != 0)
					return PSize;

				SysInfo Inf;
				Native.GetSystemInfo(out Inf);
				PSize = (uint)Inf.PageSize;
				return PageSize;
			}
		}

		static HashSet<HackyPointer> HackyPointers;

		static HackyPointer() {
			HackyPointers = new HashSet<HackyPointer>();
			Native.AddVectoredExceptionHandler(0, (H) => {
				uint Code = H->ExceptionRecord->ExceptionCode;
				// Breakpoints
				if (Code == 0x80000003)
					return VHRet.ContinueSearch;

				Console.WriteLine("Code: 0x{0:X}", Code);
				//Console.WriteLine(H->ExceptionRecord->ToString());

				HackyPointer Ptr = null;
				bool Write = false;
				IntPtr* Info = (IntPtr*)H->ExceptionRecord->ExceptionInformation;
				if (H->ExceptionRecord->NumberParameters >= 2) {
					IntPtr Addr = Info[1];
					foreach (var HP in HackyPointers)
						if (HP.Pointer.ToInt64() <= Addr.ToInt64() && (HP.Pointer.ToInt64() + HP.Size) > Addr.ToInt64()) {
							Ptr = HP;
							Write = ((IntPtr*)H->ExceptionRecord->ExceptionInformation)[0].ToInt32() == 1;
							break;
						}
				}

				/*// Access violation
				if (Code == 0xC0000005) {
					Debugger.Break();

					if (Ptr != null)
						Ptr.VirtualProtect(MemProtection.ReadWrite | MemProtection.PageGuard);
					return VHRet.ContinueExecution;
				}*/

				// Page guard
				if (Code == 0x80000001 && H->ExceptionRecord->NumberParameters == 2) {
					if (Ptr != null) {
						Ptr.VirtualProtect(MemProtection.ReadWrite);
						Console.WriteLine("{0} to {1}", Write ? "Write" : "Read", Ptr);
					}
					return VHRet.ContinueExecution;
				}

				return VHRet.ContinueSearch;
			});
		}
		

		public HackyPointer(uint Size) {
			this.Size = Size;
			Pointer = Native.VirtualAlloc(IntPtr.Zero, Size, AllocType.Commit | AllocType.Reserve, MemProtection.ReadWrite);
			if (Pointer == IntPtr.Zero)
				throw new Exception("OH NO! IT'S NULL!");

			VirtualProtect(MemProtection.ReadWrite | MemProtection.PageGuard);
			HackyPointers.Add(this);
		}

		public void Dispose() {
			HackyPointers.Remove(this);
		}

		public MemProtection VirtualProtect(MemProtection P) {
			MemProtection Old;
			if (!Native.VirtualProtect(Pointer, Size, P, out Old))
				throw new Exception();
			return Old;
		}

		public override string ToString() {
			return string.Format("(0x{0:X}, Len {1})", Pointer.ToInt64(), Size);
		}

		public static implicit operator void*(HackyPointer Ptr) {
			return Ptr.Pointer.ToPointer();
		}

		public static implicit operator IntPtr(HackyPointer Ptr) {
			return Ptr.Pointer;
		}
	}
}