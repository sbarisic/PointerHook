using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using System.Runtime.ExceptionServices;

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
		public IntPtr ExceptionRecord;
		public IntPtr ExceptionAddress;
		public uint NumberParameters;
		public fixed uint ExceptionInformation[15];
	}

	[StructLayout(LayoutKind.Sequential, Pack = 1)]
	unsafe struct EXCEPTION_PTRS {
		public EXCEPTION_RECORD* ExceptionRecord;
		public IntPtr ContextRecord;
	}

	[UnmanagedFunctionPointer(CallingConvention.StdCall)]
	unsafe delegate long VectoredHandlerFunc(EXCEPTION_PTRS* Ptrs);

	static unsafe class Native {
		[DllImport("kernel32", SetLastError = true)]
		public static extern void GetSystemInfo(out SysInfo lpSystemInfo);

		[DllImport("kernel32.dll", SetLastError = true)]
		public static extern IntPtr VirtualAlloc(IntPtr Addr, uint Size, AllocType AType, MemProtection Protect);

		[DllImport("kernel32.dll", SetLastError = true)]
		public static extern bool VirtualProtect(IntPtr Addr, uint Size, MemProtection NewProtect, out MemProtection OldProtect);
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

			AppDomain.CurrentDomain.UnhandledException += (S, E) => {
				if (E.ExceptionObject is SEHException) {
					SEHException SE = E.ExceptionObject as SEHException;

					int Code = Marshal.GetExceptionCode();
					EXCEPTION_PTRS* EPtrs = (EXCEPTION_PTRS*)Marshal.GetExceptionPointers().ToPointer();

					Console.WriteLine("Code: {0}", Code);
				}
			};
		}

		public HackyPointer(uint Size) {
			this.Size = Size;
			Pointer = Native.VirtualAlloc(IntPtr.Zero, Size, AllocType.Reserve | AllocType.Commit,
				MemProtection.ReadOnly | MemProtection.PageGuard);
			if (Pointer == IntPtr.Zero)
				throw new Exception("OH NO! IT'S NULL!");

			HackyPointers.Add(this);
		}

		public void Dispose() {
			HackyPointers.Remove(this);
		}

		void OnException(object Sender, UnhandledExceptionEventArgs E) {
			if (E.ExceptionObject is SEHException) {
				SEHException SEH = E.ExceptionObject as SEHException;

				Console.WriteLine(SEH);
			}
		}

		public override string ToString() {
			return string.Format("(@ {0}, Len {1})", Pointer, Size);
		}

		public static implicit operator void*(HackyPointer Ptr) {
			return Ptr.Pointer.ToPointer();
		}

		public static implicit operator IntPtr(HackyPointer Ptr) {
			return Ptr.Pointer;
		}
	}
}