using Microsoft.Win32.SafeHandles;
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace vSeriousSDK
{
    public class VSeriousDevice : IDisposable
    {
        private static readonly string devicePath = "\\\\.\\vSerious";

        // Two handles to the controller device. The Windows I/O manager
        // serializes IOCTLs on the same synchronous handle — so a parked
        // IOCTL_VSERIOUS_READ (waiting for Cristina to write) blocks every
        // other call (including the heartbeat's IOCTL_VSERIOUS_WRITE).
        // Splitting Read/Write across two handles lets them run concurrently.
        private SafeFileHandle deviceHandle;       // SetActive, SetCOMPort, Write
        private SafeFileHandle deviceReadHandle;   // Read only
        private SafeFileHandle comHandle;
        private string comPort;

        private bool disposed = false;

        private const uint FILE_DEVICE_SERIAL_PORT = 0x0000001b;
        private const uint METHOD_BUFFERED = 0;
        private const uint FILE_READ_ACCESS = 0x0001;
        private const uint FILE_WRITE_ACCESS = 0x0002;

        private static uint CTL_CODE(uint deviceType, uint function, uint method, uint access)
            => (deviceType << 16) | (access << 14) | (function << 2) | method;

        private static readonly uint IOCTL_VSERIOUS_SET_ACTIVE = CTL_CODE(FILE_DEVICE_SERIAL_PORT, 0x800, METHOD_BUFFERED, FILE_WRITE_ACCESS);
        private static readonly uint IOCTL_VSERIOUS_GET_ACTIVE = CTL_CODE(FILE_DEVICE_SERIAL_PORT, 0x801, METHOD_BUFFERED, FILE_READ_ACCESS);
        private static readonly uint IOCTL_VSERIOUS_SET_COM_NAME = CTL_CODE(FILE_DEVICE_SERIAL_PORT, 0x802, METHOD_BUFFERED, FILE_WRITE_ACCESS);
        private static readonly uint IOCTL_VSERIOUS_GET_COM_NAME = CTL_CODE(FILE_DEVICE_SERIAL_PORT, 0x803, METHOD_BUFFERED, FILE_READ_ACCESS);
        // Hardware-side data path. Cristina uses ReadFile/WriteFile on
        // \\.\COMx; we use these on \\.\vSerious so the per-direction
        // ring buffers stay decoupled (no echo, no race).
        private static readonly uint IOCTL_VSERIOUS_READ = CTL_CODE(FILE_DEVICE_SERIAL_PORT, 0x804, METHOD_BUFFERED, FILE_READ_ACCESS);
        private static readonly uint IOCTL_VSERIOUS_WRITE = CTL_CODE(FILE_DEVICE_SERIAL_PORT, 0x805, METHOD_BUFFERED, FILE_WRITE_ACCESS);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern SafeFileHandle CreateFile(
            string lpFileName,
            FileAccess dwDesiredAccess,
            FileShare dwShareMode,
            IntPtr lpSecurityAttributes,
            FileMode dwCreationDisposition,
            int dwFlagsAndAttributes,
            IntPtr hTemplateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool DeviceIoControl(
            SafeFileHandle hDevice,
            uint dwIoControlCode,
            IntPtr inBuffer,
            int nInBufferSize,
            IntPtr outBuffer,
            int nOutBufferSize,
            out int bytesReturned,
            IntPtr overlapped);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool ReadFile(
            SafeFileHandle hFile,
            byte[] lpBuffer,
            int nNumberOfBytesToRead,
            out int lpNumberOfBytesRead,
            IntPtr lpOverlapped);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool WriteFile(
            SafeFileHandle hFile,
            byte[] lpBuffer,
            int nNumberOfBytesToWrite,
            out int lpNumberOfBytesWritten,
            IntPtr lpOverlapped);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetCommTimeouts(SafeFileHandle hFile, ref COMMTIMEOUTS lpCommTimeouts);

        [StructLayout(LayoutKind.Sequential)]
        private struct COMMTIMEOUTS
        {
            public uint ReadIntervalTimeout;
            public uint ReadTotalTimeoutMultiplier;
            public uint ReadTotalTimeoutConstant;
            public uint WriteTotalTimeoutMultiplier;
            public uint WriteTotalTimeoutConstant;
        }

        public VSeriousDevice()
        {
            deviceHandle = OpenControllerHandle();
            deviceReadHandle = OpenControllerHandle();
        }

        private static SafeFileHandle OpenControllerHandle()
        {
            var handle = CreateFile(devicePath,
                FileAccess.ReadWrite,
                FileShare.ReadWrite,
                IntPtr.Zero,
                FileMode.Open,
                0,
                IntPtr.Zero);

            if (handle.IsInvalid)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Failed to open device handle.");
            }
            return handle;
        }

        public void SetCOMPort(string comPort)
        {
            if (comHandle != null && !comHandle.IsInvalid)
            {
                throw new ApplicationException("Invalid State");
            }

            if (string.IsNullOrWhiteSpace(comPort))
            {
                throw new ArgumentNullException(nameof(comPort));
            }

            string bareName = comPort;
            if (bareName.StartsWith(@"\\.\") || bareName.StartsWith(@"\\?\"))
            {
                bareName = bareName.Substring(4);
            }

            this.comPort = @"\\.\" + bareName;

            byte[] stringBytes = Encoding.Unicode.GetBytes(bareName);
            int inSize = stringBytes.Length;
            IntPtr inPtr = Marshal.AllocHGlobal(inSize);

            try
            {
                Marshal.Copy(stringBytes, 0, inPtr, inSize);

                if (!DeviceIoControl(
                    deviceHandle,
                    IOCTL_VSERIOUS_SET_COM_NAME,
                    inPtr,
                    inSize,
                    IntPtr.Zero,
                    0,
                    out _,
                    IntPtr.Zero))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "Failed to set COM port name.");
                }
            }
            finally
            {
                Marshal.FreeHGlobal(inPtr);
            }
        }

        public string GetCOMPort()
        {
            if (string.IsNullOrWhiteSpace(this.comPort))
            {
                throw new ApplicationException(nameof(comPort));
            }

            const int bufferSize = 64; 
            IntPtr outPtr = Marshal.AllocHGlobal(bufferSize);

            try
            {
                if (!DeviceIoControl(
                    deviceHandle,
                    IOCTL_VSERIOUS_GET_COM_NAME,
                    IntPtr.Zero,
                    0,
                    outPtr,
                    bufferSize,
                    out int bytesReturned,
                    IntPtr.Zero))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "Failed to get COM port name.");
                }

                return Marshal.PtrToStringUni(outPtr, bytesReturned / 2); 
            }
            finally
            {
                Marshal.FreeHGlobal(outPtr);
            }
        }

        public void SetActive(bool active)
        {
            if (!active)
            {
                // Cancel any in-flight Read by recycling the read handle —
                // closing the handle forces the parked IOCTL_VSERIOUS_READ to
                // complete with STATUS_CANCELLED, freeing the read loop. Then
                // SetActiveIoctl tells the driver to flip the active flag.
                if (deviceReadHandle != null && !deviceReadHandle.IsInvalid)
                {
                    deviceReadHandle.Close();
                    deviceReadHandle.Dispose();
                    deviceReadHandle = null;
                }
                if (comHandle != null)
                {
                    comHandle.Close();
                    comHandle.Dispose();
                    comHandle = null;
                }
            }

            SetActiveIoctl(active);

            if (!active) return;

            // Re-open the read handle for the new session.
            if (deviceReadHandle == null || deviceReadHandle.IsInvalid)
            {
                deviceReadHandle = OpenControllerHandle();
            }

            try
            {
                if (string.IsNullOrWhiteSpace(comPort))
                    throw new InvalidOperationException("COM port must be set before activating.");

                // PnP enumeration of the new PDO is asynchronous — the symbolic
                // link may not exist yet by the time SetActive returns. Retry
                // briefly before giving up.
                int lastError = 0;
                for (int attempt = 0; attempt < 20; attempt++)
                {
                    comHandle = CreateFile(this.comPort,
                        FileAccess.ReadWrite,
                        FileShare.ReadWrite,
                        IntPtr.Zero,
                        FileMode.Open,
                        0,
                        IntPtr.Zero);

                    if (!comHandle.IsInvalid)
                        break;

                    lastError = Marshal.GetLastWin32Error();
                    comHandle.Dispose();
                    comHandle = null;
                    Thread.Sleep(100);
                }

                if (comHandle == null || comHandle.IsInvalid)
                {
                    throw new Win32Exception(lastError, "Failed to open COM handle after activation.");
                }

                // Make Read block until data is available; otherwise the default
                // timeouts can cause Read to return zero bytes immediately.
                COMMTIMEOUTS timeouts = new COMMTIMEOUTS
                {
                    ReadIntervalTimeout = 0xFFFFFFFF,
                    ReadTotalTimeoutMultiplier = 0,
                    ReadTotalTimeoutConstant = 0,
                    WriteTotalTimeoutMultiplier = 0,
                    WriteTotalTimeoutConstant = 1000
                };
                SetCommTimeouts(comHandle, ref timeouts);
            }
            catch
            {
                // Driver flipped Active=TRUE and reported the PDO, but we never
                // took ownership of the COM handle. Roll back so the controller
                // doesn't stay stuck active (which blocks SetCOMPort next time).
                try { SetActiveIoctl(false); } catch { /* best-effort */ }
                throw;
            }
        }

        private void SetActiveIoctl(bool active)
        {
            IntPtr inPtr = Marshal.AllocHGlobal(1);
            IntPtr outPtr = Marshal.AllocHGlobal(1);

            try
            {
                Marshal.WriteByte(inPtr, active ? (byte)1 : (byte)0);

                if (!DeviceIoControl(
                    deviceHandle,
                    IOCTL_VSERIOUS_SET_ACTIVE,
                    inPtr,
                    1,
                    outPtr,
                    1,
                    out _,
                    IntPtr.Zero))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "Failed to set device active state.");
                }
            }
            finally
            {
                Marshal.FreeHGlobal(inPtr);
                Marshal.FreeHGlobal(outPtr);
            }
        }

        public bool GetActive()
        {
            IntPtr inPtr = Marshal.AllocHGlobal(1);
            IntPtr outPtr = Marshal.AllocHGlobal(1);

            try
            {
                Marshal.WriteByte(inPtr, 0);

                if (!DeviceIoControl(
                    deviceHandle,
                    IOCTL_VSERIOUS_GET_ACTIVE,
                    inPtr,
                    1,
                    outPtr,
                    1,
                    out _,
                    IntPtr.Zero))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "Failed to get device active state.");
                }

                return Marshal.ReadByte(outPtr) != 0;
            }
            finally
            {
                Marshal.FreeHGlobal(inPtr);
                Marshal.FreeHGlobal(outPtr);
            }
        }

        public void Write(byte[] data)
        {
            if (data == null || data.Length == 0)
                throw new ArgumentNullException(nameof(data));

            if (deviceHandle == null || deviceHandle.IsInvalid)
                throw new InvalidOperationException("Device handle is not open.");

            IntPtr inBuf = Marshal.AllocHGlobal(data.Length);
            try
            {
                Marshal.Copy(data, 0, inBuf, data.Length);
                if (!DeviceIoControl(deviceHandle, IOCTL_VSERIOUS_WRITE,
                        inBuf, data.Length, IntPtr.Zero, 0,
                        out int _, IntPtr.Zero))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error(),
                        "IOCTL_VSERIOUS_WRITE failed.");
                }
            }
            finally
            {
                Marshal.FreeHGlobal(inBuf);
            }
        }

        public byte[] Read(int length)
        {
            if (length <= 0)
                throw new ArgumentOutOfRangeException(nameof(length), "Length must be positive.");

            if (deviceReadHandle == null || deviceReadHandle.IsInvalid)
                throw new InvalidOperationException("Device read handle is not open.");

            IntPtr outBuf = Marshal.AllocHGlobal(length);
            try
            {
                // Uses the dedicated read handle so the IOCTL can park in the
                // driver's SdkReadQueue without blocking the write handle.
                if (!DeviceIoControl(deviceReadHandle, IOCTL_VSERIOUS_READ,
                        IntPtr.Zero, 0, outBuf, length,
                        out int bytesRead, IntPtr.Zero))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error(),
                        "IOCTL_VSERIOUS_READ failed.");
                }
                byte[] buffer = new byte[bytesRead];
                if (bytesRead > 0) Marshal.Copy(outBuf, buffer, 0, bytesRead);
                return buffer;
            }
            finally
            {
                Marshal.FreeHGlobal(outBuf);
            }
        }

        public void Dispose()
        {
            if (!disposed)
            {
                if (deviceHandle != null && !deviceHandle.IsInvalid)
                {
                    deviceHandle.Dispose();
                }
                if (deviceReadHandle != null && !deviceReadHandle.IsInvalid)
                {
                    deviceReadHandle.Dispose();
                }
                if (comHandle != null && !comHandle.IsInvalid)
                {
                    comHandle.Dispose();
                }
                disposed = true;
                GC.SuppressFinalize(this);
            }
        }

        ~VSeriousDevice()
        {
            Dispose();
        }
    }

}
