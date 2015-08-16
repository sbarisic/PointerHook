using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PointerHook {
	unsafe class HackyPointer {
		IntPtr InternalPtr;

		public HackyPointer(int Size) {

		}

		public static implicit operator void*(HackyPointer Ptr) {
			return Ptr.InternalPtr.ToPointer();
		}

		public static implicit operator IntPtr(HackyPointer Ptr) {
			return Ptr.InternalPtr;
		}
	}
}
