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
        private const string devicePath = @"\\.\vSerious";

        private SafeFileHandle deviceHandle;
        private SafeFileHandle comHandle;
        private string comPort;

        private bool disposed = false;

        private const uint GENERIC_READ_WRITE = 0xC0000000;
        private const uint FILE_DEVICE_SERIAL_PORT = 0x0000001b;
        private const uint METHOD_BUFFERED = 0;
        private const uint FILE_WRITE_DATA = 0x0002;
        private const uint FILE_READ_DATA = 0x0001;

        private static uint CTL_CODE(uint deviceType, uint function, uint method, uint access)
            => (deviceType << 16) | (access << 14) | (function << 2) | method;

        private static readonly uint IOCTL_VSERIOUS_SET_ACTIVE = CTL_CODE(FILE_DEVICE_SERIAL_PORT, 0x800, METHOD_BUFFERED, FILE_WRITE_DATA);
        private static readonly uint IOCTL_VSERIOUS_GET_ACTIVE = CTL_CODE(FILE_DEVICE_SERIAL_PORT, 0x801, METHOD_BUFFERED, FILE_READ_DATA);
        private static readonly uint IOCTL_VSERIOUS_SET_COM_NAME = CTL_CODE(FILE_DEVICE_SERIAL_PORT, 0x802, METHOD_BUFFERED, FILE_WRITE_DATA);
        private static readonly uint IOCTL_VSERIOUS_GET_COM_NAME = CTL_CODE(FILE_DEVICE_SERIAL_PORT, 0x803, METHOD_BUFFERED, FILE_READ_DATA);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern SafeFileHandle CreateFile(
            string lpFileName,
            uint dwDesiredAccess,
            FileShare dwShareMode,
            IntPtr lpSecurityAttributes,
            FileMode dwCreationDisposition,
            int dwFlagsAndAttributes,
            IntPtr hTemplateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool DeviceIoControl(
            SafeFileHandle hDevice,
            uint dwIoControlCode,
            [In] byte[] inBuffer,
            int nInBufferSize,
            [Out] byte[] outBuffer,
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
            deviceHandle = CreateFile(devicePath,
                GENERIC_READ_WRITE,
                FileShare.ReadWrite,
                IntPtr.Zero,
                FileMode.Open,
                0,
                IntPtr.Zero);

            if (deviceHandle.IsInvalid) {
                int errorCode = Marshal.GetLastWin32Error();
                throw new Win32Exception(errorCode, $"Failed to open device handle. Error {errorCode}");
            }
        }

        public void SetCOMPort(string comPort)
        {
            if (comHandle != null && !comHandle.IsInvalid)
            {
                throw new ApplicationException("Device handle already open.");
            }

            if (string.IsNullOrWhiteSpace(comPort))
            {
                throw new ArgumentNullException(nameof(comPort));
            }

            byte[] comPortBytes = Encoding.Unicode.GetBytes(comPort + "\0");

            if (!DeviceIoControl(
                deviceHandle,
                IOCTL_VSERIOUS_SET_COM_NAME,
                comPortBytes,
                comPortBytes.Length,
                null,
                0,
                out _,
                IntPtr.Zero))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Failed to set COM port name.");
            }
            this.comPort = comPort;
        }

        public string GetCOMPort()
        {
            const int bufferSize = 64; 
            byte[] outBuffer = new byte[bufferSize];

            if (!DeviceIoControl(
                deviceHandle,
                IOCTL_VSERIOUS_GET_COM_NAME,
                null,
                0,
                outBuffer,
                outBuffer.Length,
                out int bytesReturned,
                IntPtr.Zero))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Failed to get COM port name.");
            }

            return Encoding.Unicode.GetString(outBuffer, 0, bytesReturned).TrimEnd('\0');
        }

        public void SetActive(bool active)
        {
            if (string.IsNullOrWhiteSpace(comPort))
                throw new InvalidOperationException("COM port must be set before activating.");

            if (!active && comHandle != null)
            {
                comHandle.Close();
                comHandle.Dispose();
                comHandle = null;
            }

            byte[] inBuffer = new byte[] { (byte)(active ? 1 : 0) };

            if (!DeviceIoControl(
                deviceHandle,
                IOCTL_VSERIOUS_SET_ACTIVE,
                inBuffer,
                inBuffer.Length,
                null,
                0,
                out _,
                IntPtr.Zero))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Failed to set device active state.");
            }

            if (active) {
                int attempts = 0;
                string fullPath = $@"\\.\{comPort}";

                while (attempts < 20) {
                    comHandle = CreateFile(
                        fullPath,
                        GENERIC_READ_WRITE,
                        FileShare.None,
                        IntPtr.Zero,
                        FileMode.Open,
                        0,
                        IntPtr.Zero);

                    if (!comHandle.IsInvalid) {
                        COMMTIMEOUTS timeouts = new COMMTIMEOUTS
                        {
                            ReadIntervalTimeout = 0xFFFFFFFF, 
                            ReadTotalTimeoutMultiplier = 0,
                            ReadTotalTimeoutConstant = 0,
                            WriteTotalTimeoutMultiplier = 0,
                            WriteTotalTimeoutConstant = 1000
                        };
                        SetCommTimeouts(comHandle, ref timeouts);
                        return;
                    }

                    int error = Marshal.GetLastWin32Error();
                    Thread.Sleep(100);
                    attempts++;
                }

                throw new TimeoutException($"Timed out waiting for {comPort} to appear.");
            } else {
                if (comHandle != null && !comHandle.IsInvalid) {
                    comHandle.Close();
                    comHandle.Dispose();
                    comHandle = null;
                }
            }
        }

        public bool GetActive()
        {
            byte[] outBuffer = new byte[1];

            if (!DeviceIoControl(
                deviceHandle,
                IOCTL_VSERIOUS_GET_ACTIVE,
                null,
                0,
                outBuffer,
                outBuffer.Length,
                out _,
                IntPtr.Zero))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Failed to get device active state.");
            }

            return outBuffer[0] != 0;
        }

        public void Write(byte[] data)
        {
            if (data == null || data.Length == 0)
                throw new ArgumentNullException(nameof(data));

            if (comHandle == null || comHandle.IsInvalid)
                throw new InvalidOperationException("COM port is not active.");

            bool success = WriteFile(
                comHandle,
                data,
                data.Length,
                out int bytesWritten,
                IntPtr.Zero);

            if (!success || bytesWritten != data.Length)
            {
                throw new IOException("WriteFile failed or wrote incomplete data.",
                    new Win32Exception(Marshal.GetLastWin32Error()));
            }
        }

        public byte[] Read(int length)
        {
            if (length <= 0)
                throw new ArgumentOutOfRangeException(nameof(length), "Length must be positive.");

            if (comHandle == null || comHandle.IsInvalid)
                throw new InvalidOperationException("COM port is not active.");

            byte[] buffer = new byte[length];

            bool success = ReadFile(
                comHandle,
                buffer,
                length,
                out int bytesRead,
                IntPtr.Zero);

            if (!success)
            {
                throw new IOException("ReadFile failed.",
                    new Win32Exception(Marshal.GetLastWin32Error()));
            }

            if (bytesRead == 0)
            {
                return Array.Empty<byte>();
            }

            if (bytesRead != length)
            {
                Array.Resize(ref buffer, bytesRead);
            }

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
