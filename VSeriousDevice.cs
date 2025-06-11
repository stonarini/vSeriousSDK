using Microsoft.Win32.SafeHandles;
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace vSeriousSDK
{
    public class VSeriousDevice : IDisposable
    {
        private static readonly string devicePath = "\\\\.\\vSerious";

        private SafeFileHandle deviceHandle;
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

        public VSeriousDevice()
        {
            deviceHandle = CreateFile(devicePath,
                FileAccess.ReadWrite,
                FileShare.ReadWrite,
                IntPtr.Zero,
                FileMode.Open,
                0,
                IntPtr.Zero);

            if (deviceHandle.IsInvalid)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Failed to open device handle.");
            }
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

            if (!comPort.StartsWith(@"\\.\"))
            {
                comPort = @"\\.\" + comPort;
            }

            this.comPort = comPort;
            byte[] stringBytes = Encoding.Unicode.GetBytes(comPort);
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
            if (!active && comHandle != null)
            {
                comHandle.Close();
                comHandle.Dispose();
                comHandle = null;
            }

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

            if (active)
            {
                if (string.IsNullOrWhiteSpace(comPort))
                    throw new InvalidOperationException("COM port must be set before activating.");

                comHandle = CreateFile(this.comPort,
                    FileAccess.ReadWrite,
                    FileShare.ReadWrite,
                    IntPtr.Zero,
                    FileMode.Open,
                    0,
                    IntPtr.Zero);

                if (comHandle.IsInvalid)
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "Failed to open COM handle.");
                }
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

            if (comHandle == null || comHandle.IsInvalid)
                throw new InvalidOperationException("COM port is not active.");

            if (!WriteFile(comHandle, data, data.Length, out int bytesWritten, IntPtr.Zero))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "WriteFile failed.");
            }
        }

        public byte[] Read(int length)
        {
            if (length <= 0)
                throw new ArgumentOutOfRangeException(nameof(length), "Length must be positive.");

            if (comHandle == null || comHandle.IsInvalid)
                throw new InvalidOperationException("COM port is not active.");

            byte[] buffer = new byte[length];

            if (!ReadFile(comHandle, buffer, length, out int bytesRead, IntPtr.Zero))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "ReadFile failed.");
            }

            Array.Resize(ref buffer, bytesRead);
            return buffer;
        }

        public void Dispose()
        {
            if (!disposed)
            {
                if (deviceHandle != null && !deviceHandle.IsInvalid)
                {
                    deviceHandle.Dispose();
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
