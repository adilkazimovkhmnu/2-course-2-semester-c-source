using System;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Security.Cryptography;
using System.Numerics;
using System.IO;

namespace SecureSocketApp
{
    public class CryptoHelper
    {
        private static readonly byte[] SBox = new byte[256]
        {
            0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
            0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
            0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
            0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
            0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
            0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
            0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
            0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
            0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
            0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
            0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
            0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
            0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
            0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
            0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
            0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
        };


        public static byte[] Encrypt(byte[] data, byte[] key)
        {
            byte[] encrypted = new byte[data.Length];
            for (int i = 0; i < data.Length; i++)
            {
                encrypted[i] = SBox[data[i] ^ key[i % key.Length]];
            }
            return encrypted;
        }

        public static byte[] Decrypt(byte[] data, byte[] key)
        {
            byte[] decrypted = new byte[data.Length];
            for (int i = 0; i < data.Length; i++)
            {
                int index = Array.IndexOf(SBox, data[i]);
                decrypted[i] = index >= 0 ? (byte)(index ^ key[i % key.Length]) : (byte)0;
            }
            return decrypted;
        }
    }

    public class ProtectionHelper
    {
        public static string GetSystemFingerprint()
        {
            string cpuId = GetCpuId();
            string diskId = GetDiskId();
            return HashString(cpuId + diskId);
        }

        private static string GetCpuId()
        {
            try { return Environment.ProcessorCount + Environment.MachineName; }
            catch { return "DEFAULT_CPU_ID"; }
        }

        private static string GetDiskId()
        {
            try { return Environment.CurrentDirectory.GetHashCode().ToString(); }
            catch { return "DEFAULT_DISK_ID"; }
        }

        private static string HashString(string input)
        {
            using var sha256 = SHA256.Create();
            return Convert.ToBase64String(sha256.ComputeHash(Encoding.UTF8.GetBytes(input)));
        }
    }

    public class KeyExchange
    {
        private static readonly BigInteger p = BigInteger.Parse("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF", System.Globalization.NumberStyles.HexNumber);
        private static readonly BigInteger g = 2;

        public static BigInteger GeneratePrivateKey()
        {
            Random random = new Random();
            byte[] bytes = new byte[32];
            random.NextBytes(bytes);
            byte[] positiveBytes = new byte[bytes.Length + 1];
            Array.Copy(bytes, positiveBytes, bytes.Length);
            return new BigInteger(positiveBytes) % (p - 1) + 1;
        }

        public static BigInteger CalculatePublicKey(BigInteger privateKey)
            => BigInteger.ModPow(g, privateKey, p);

        public static BigInteger CalculateSharedSecret(BigInteger privateKey, BigInteger otherPublicKey)
            => BigInteger.ModPow(otherPublicKey, privateKey, p);

        public static byte[] GetSessionKey(BigInteger sharedSecret)
        {
            using var sha256 = SHA256.Create();
            return sha256.ComputeHash(sharedSecret.ToByteArray());
        }
    }

    public class SecureServer
    {
        private static int port = 8005;
        private static string serverFingerprint = ProtectionHelper.GetSystemFingerprint();
        private static BigInteger serverPrivateKey = KeyExchange.GeneratePrivateKey();
        private static BigInteger serverPublicKey = KeyExchange.CalculatePublicKey(serverPrivateKey);

        public static void Start()
        {
            IPEndPoint ipPoint = new IPEndPoint(IPAddress.Parse("127.0.0.1"), port);
            Socket listenSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);

            try
            {
                listenSocket.Bind(ipPoint);
                listenSocket.Listen(10);
                Console.WriteLine("Сервер запущено. Очікування підключень...");
                Console.WriteLine($"Fingerprint сервера: {serverFingerprint}");
                Console.WriteLine($"Публічний ключ сервера: {serverPublicKey}");

                while (true)
                {
                    Socket handler = listenSocket.Accept();
                    Console.WriteLine("\nНове підключення!");

                    try
                    {
                        byte[] clientPublicKeyBytes = new byte[256];
                        int bytesReceived = handler.Receive(clientPublicKeyBytes);
                        BigInteger clientPublicKey = new BigInteger(new ReadOnlySpan<byte>(clientPublicKeyBytes, 0, bytesReceived));
                        Console.WriteLine($"Отримано публічний ключ клієнта: {clientPublicKey}");

                        byte[] serverPubKeyBytes = serverPublicKey.ToByteArray();
                        handler.Send(serverPubKeyBytes);

                        BigInteger sharedSecret = KeyExchange.CalculateSharedSecret(serverPrivateKey, clientPublicKey);
                        byte[] sessionKey = KeyExchange.GetSessionKey(sharedSecret);
                        Console.WriteLine($"Створено ключ сесії: {Convert.ToBase64String(sessionKey)}");

                        while (true)
                        {
                            byte[] encryptedData = new byte[1024];
                            bytesReceived = handler.Receive(encryptedData);
                            if (bytesReceived == 0) break;

                            byte[] decryptedData = CryptoHelper.Decrypt(encryptedData[..bytesReceived], sessionKey);
                            string message = Encoding.UTF8.GetString(decryptedData).TrimEnd('\0');
                            Console.WriteLine($"Отримано повідомлення: {message}");

                            if (message.ToLower() == "exit") break;

                            string response = $"Сервер отримав ваше повідомлення: {message}";
                            byte[] responseBytes = Encoding.UTF8.GetBytes(response);
                            byte[] encryptedResponse = CryptoHelper.Encrypt(responseBytes, sessionKey);
                            handler.Send(encryptedResponse);
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Помилка: {ex.Message}");
                    }
                    finally
                    {
                        handler.Shutdown(SocketShutdown.Both);
                        handler.Close();
                        Console.WriteLine("З'єднання закрито.");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
        }
    }

    public class SecureClient
    {
        private static int port = 8005;
        private static string address = "127.0.0.1";
        private static BigInteger clientPrivateKey;
        private static BigInteger clientPublicKey;
        private static byte[] sessionKey;

        static SecureClient()
        {
            clientPrivateKey = KeyExchange.GeneratePrivateKey();
            clientPublicKey = KeyExchange.CalculatePublicKey(clientPrivateKey);
        }

        public static void Start()
        {
            try
            {
                IPEndPoint ipPoint = new IPEndPoint(IPAddress.Parse(address), port);
                Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);

                Console.WriteLine($"Fingerprint клієнта: {ProtectionHelper.GetSystemFingerprint()}");
                Console.WriteLine($"Публічний ключ клієнта: {clientPublicKey}");

                socket.Connect(ipPoint);

                byte[] clientPubKeyBytes = clientPublicKey.ToByteArray();
                socket.Send(clientPubKeyBytes);

                byte[] serverPublicKeyBytes = new byte[256];
                int bytesReceived = socket.Receive(serverPublicKeyBytes);
                BigInteger serverPublicKey = new BigInteger(new ReadOnlySpan<byte>(serverPublicKeyBytes, 0, bytesReceived));
                Console.WriteLine($"Отримано публічний ключ сервера: {serverPublicKey}");

                BigInteger sharedSecret = KeyExchange.CalculateSharedSecret(clientPrivateKey, serverPublicKey);
                sessionKey = KeyExchange.GetSessionKey(sharedSecret);
                Console.WriteLine($"Створено ключ сесії: {Convert.ToBase64String(sessionKey)}");

                while (true)
                {
                    Console.Write("Введіть повідомлення: ");
                    string message = Console.ReadLine();
                    if (string.IsNullOrWhiteSpace(message)) continue;

                    byte[] messageBytes = Encoding.UTF8.GetBytes(message);
                    byte[] encryptedMessage = CryptoHelper.Encrypt(messageBytes, sessionKey);
                    socket.Send(encryptedMessage);

                    if (message.ToLower() == "exit") break;

                    byte[] encryptedResponse = new byte[1024];
                    bytesReceived = socket.Receive(encryptedResponse);
                    byte[] decryptedResponse = CryptoHelper.Decrypt(encryptedResponse[..bytesReceived], sessionKey);
                    string response = Encoding.UTF8.GetString(decryptedResponse).TrimEnd('\0');
                    Console.WriteLine($"Відповідь сервера: {response}");
                }

                socket.Shutdown(SocketShutdown.Both);
                socket.Close();
            }
            catch (Exception ex)
            {
                Console.WriteLine("Помилка: " + ex.Message);
            }
        }
    }

    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Оберіть режим:");
            Console.WriteLine("1 - Сервер");
            Console.WriteLine("2 - Клієнт");
            Console.Write("Ваш вибір: ");

            string choice = Console.ReadLine();

            if (choice == "1") SecureServer.Start();
            else if (choice == "2") SecureClient.Start();
            else Console.WriteLine("Невірний вибір");
        }
    }
}