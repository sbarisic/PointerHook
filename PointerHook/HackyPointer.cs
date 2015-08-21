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
	public enum FreeType : uint {
		Decommit = 0x4000,
		Release = 0x8000,
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
		public void* ExceptionAddress;
		public uint NumberParameters;
		public fixed int ExceptionInformation[15];
	}

	[StructLayout(LayoutKind.Sequential, Pack = 1)]
	unsafe struct FLOATING_SAVE_AREA_WIN {
		public uint ControlWord;
		public uint StatusWord;
		public uint TagWord;
		public uint ErrorOffset;
		public uint ErrorSelector;
		public uint DataOffset;
		public uint DataSelector;
		public fixed byte RegisterArea[80];
		public uint Cr0NpxState;
	}

	[StructLayout(LayoutKind.Sequential, Pack = 1)]
	unsafe struct CONTEXT {
		public uint ContextFlags;
		public uint Dr0;
		public uint Dr1;
		public uint Dr2;
		public uint Dr3;
		public uint Dr6;
		public uint Dr7;
		public FLOATING_SAVE_AREA_WIN FloatSave;
		public uint SegGs;
		public uint SegFs;
		public uint SegEs;
		public uint SegDs;
		public uint Edi;
		public uint Esi;
		public uint Ebx;
		public uint Edx;
		public uint Ecx;
		public uint Eax;
		public uint Ebp;
		public uint Eip;
		public uint SegCs;
		public uint EFlags;
		public uint Esp;
		public uint SegSs;
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
		public static extern bool VirtualFree(IntPtr Addr, uint Size = 0, FreeType FType = FreeType.Release);

		[DllImport("kernel32", SetLastError = true, CallingConvention = CallingConvention.Winapi)]
		public static extern bool VirtualProtect(IntPtr Addr, uint Size, MemProtection NewProtect, out MemProtection OldProtect);

		[DllImport("kernel32", SetLastError = true, CallingConvention = CallingConvention.Winapi)]
		public static extern IntPtr AddVectoredExceptionHandler(int First, VectoredHandlerFunc Handler);

		[DllImport("kernel32", SetLastError = true, CallingConvention = CallingConvention.Winapi)]
		public static extern uint RemoveVectoredExceptionHandler(IntPtr Handler);

		[DllImport("kernel32", SetLastError = true, CallingConvention = CallingConvention.Winapi)]
		public static extern void RaiseException(uint Code, uint Flags, uint NumOfArgs, int* Args);
	}

	delegate void PointerAccessFunc(HackyPointer Ptr, bool Write, int ByteIdx);

	unsafe class HackyPointer : IDisposable {
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
		static IntPtr Handler;

		public static void Destroy() {
			if (Handler != IntPtr.Zero) {
				Native.RemoveVectoredExceptionHandler(Handler);
				Handler = IntPtr.Zero;
			}
		}

		static HackyPointer() {
			HackyPointers = new HashSet<HackyPointer>();

			HackyPointer LastPtr = null;
			Handler = Native.AddVectoredExceptionHandler(0, (H) => {
				uint Code = H->ExceptionRecord->ExceptionCode;
				// Breakpoints
				if (Code == 0x80000003)
					return VHRet.ContinueSearch;

				HackyPointer Ptr = LastPtr;
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

				// Single step
				if (Code == 0x80000004) {
					LastPtr = null;
					if (Ptr.Write)
						Ptr.OnAccess(Ptr, true, (int)Ptr.Offset);
					Ptr.VirtualProtect(MemProtection.ReadWrite | MemProtection.PageGuard);
				}

				// Page guard
				if (Code == 0x80000001 && H->ExceptionRecord->NumberParameters == 2 && Ptr != null) {
					LastPtr = Ptr;
					Ptr.Write = Write;
					Ptr.Offset = (uint)((IntPtr*)H->ExceptionRecord->ExceptionInformation)[1].ToInt64() -
						(uint)Ptr.Pointer.ToInt64();
					Ptr.VirtualProtect(MemProtection.ReadWrite);
					H->ContextRecord->EFlags |= 0x100;
					if (!Write)
						Ptr.OnAccess(Ptr, false, (int)Ptr.Offset);
					return VHRet.ContinueExecution;
				}

				return VHRet.ContinueSearch;
			});
		}

		PointerAccessFunc OnAccess;
		IntPtr Pointer;
		uint Size, Offset;
		bool Write;

		public HackyPointer(uint Size, PointerAccessFunc OnAccess) {
			this.Size = Size;
			this.OnAccess = OnAccess;
			Pointer = Native.VirtualAlloc(IntPtr.Zero, Size, AllocType.Commit | AllocType.Reserve, MemProtection.ReadWrite);
			if (Pointer == IntPtr.Zero)
				throw new Exception("OH NO! IT'S NULL!");

			VirtualProtect(MemProtection.ReadWrite | MemProtection.PageGuard);
			HackyPointers.Add(this);
		}

		public void Dispose() {
			HackyPointers.Remove(this);
			Native.VirtualFree(Pointer);
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
