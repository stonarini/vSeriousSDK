using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace vSeriousSDK
{
    public class VSeriousDevice : IDisposable
    {
        private SafeFileHandle deviceHandle;
        private bool disposed = false;

        private const uint FILE_DEVICE_SERIAL_PORT = 0x0000001b;
        private const uint METHOD_BUFFERED = 0;
        private const uint FILE_READ_ACCESS = 0x0001;
        private const uint FILE_WRITE_ACCESS = 0x0002;

        private static uint CTL_CODE(uint deviceType, uint function, uint method, uint access)
            => (deviceType << 16) | (access << 14) | (function << 2) | method;

        private static readonly uint IOCTL_VSERIOUS_SET_ACTIVE = CTL_CODE(FILE_DEVICE_SERIAL_PORT, 0x800, METHOD_BUFFERED, FILE_WRITE_ACCESS);
        private static readonly uint IOCTL_VSERIOUS_GET_ACTIVE = CTL_CODE(FILE_DEVICE_SERIAL_PORT, 0x801, METHOD_BUFFERED, FILE_READ_ACCESS);

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
            ref bool inBuffer,
            int nInBufferSize,
            out bool outBuffer,
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

        public VSeriousDevice(string devicePath)
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

        public void SetActive(bool active)
        {
            bool output;
            int bytesReturned;

            bool success = DeviceIoControl(
                deviceHandle,
                IOCTL_VSERIOUS_SET_ACTIVE,
                ref active,
                Marshal.SizeOf(typeof(bool)),
                out output,
                Marshal.SizeOf(typeof(bool)),
                out bytesReturned,
                IntPtr.Zero);

            if (!success)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Failed to set device active state.");
            }
        }

        public bool GetActive()
        {
            bool input = false;
            bool output;
            int bytesReturned;

            bool success = DeviceIoControl(
                deviceHandle,
                IOCTL_VSERIOUS_GET_ACTIVE,
                ref input,
                0,
                out output,
                Marshal.SizeOf(typeof(bool)),
                out bytesReturned,
                IntPtr.Zero);

            if (!success)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Failed to get device active state.");
            }

            return output;
        }

        public void Write(byte[] data)
        {
            if (!WriteFile(deviceHandle, data, data.Length, out int bytesWritten, IntPtr.Zero))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "WriteFile failed.");
            }
        }

        public byte[] Read(int length)
        {
            byte[] buffer = new byte[length];

            if (!ReadFile(deviceHandle, buffer, length, out int bytesRead, IntPtr.Zero))
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
                disposed = true;
            }
            GC.SuppressFinalize(this);
        }
    }
}
