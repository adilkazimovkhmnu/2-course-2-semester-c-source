using System;
using System.IO;
using System.Text;

namespace lab1
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.OutputEncoding = Encoding.UTF8;
            Console.WriteLine("=== ######################### ===");

            string originalText = File.ReadAllText("input.txt", Encoding.UTF8);
            byte[] originalBytes = Encoding.UTF8.GetBytes(originalText);

            byte[] keyBytes = Encoding.UTF8.GetBytes("AdilKazi"); // 8 байт

            var symmetric = new MyCryptoLibrary.SymmetricEncryptionByte();

            byte[] encryptedBytes = symmetric.Encrypt(originalBytes, keyBytes);
            string encryptedBase64 = Convert.ToBase64String(encryptedBytes);
            Console.WriteLine($"Encrypted Base64: {encryptedBase64}");

            byte[] decryptedBytes = symmetric.Decrypt(encryptedBytes, keyBytes);
            string decryptedText = Encoding.UTF8.GetString(decryptedBytes);

            Console.WriteLine($"Decrypted Text: {decryptedText}");
            Console.WriteLine("Match: " + (originalText == decryptedText));
        }
    }
}

namespace MyCryptoLibrary
{
    public class SymmetricEncryptionByte
    {
        private const int BlockSize = 16; 
        private const int Rounds = 16;
        private const int ShiftKey = 2;

        private byte[] AddPadding(byte[] input)
        {
            if (input.Length % BlockSize == 0) return input;

            int paddingBytes = BlockSize - (input.Length % BlockSize);
            byte[] padded = new byte[input.Length + paddingBytes];
            Array.Copy(input, padded, input.Length);
            for (int i = input.Length; i < padded.Length; i++)
                padded[i] = (byte)paddingBytes;

            return padded;
        }

        private byte[] RemovePadding(byte[] input)
        {
            if (input.Length == 0) return input;

            int pad = input[^1];
            if (pad < 1 || pad > BlockSize) return input;

            for (int i = input.Length - pad; i < input.Length; i++)
                if (input[i] != pad)
                    return input;

            byte[] output = new byte[input.Length - pad];
            Array.Copy(input, 0, output, 0, output.Length);
            return output;
        }

        private byte[] RotateLeftBits(byte[] data, int shift)
        {
            if (data.Length == 0) return data;
            
            int bitLen = data.Length * 8;
            shift %= bitLen;
            if (shift == 0) return (byte[])data.Clone();

            byte[] result = new byte[data.Length];

            for (int i = 0; i < bitLen; i++)
            {
                int fromPos = (i + shift) % bitLen;
                int fromByte = fromPos / 8;
                int fromBit = fromPos % 8;

                int toByte = i / 8;
                int toBit = i % 8;

                int bitVal = (data[fromByte] >> (7 - fromBit)) & 1;
                result[toByte] |= (byte)(bitVal << (7 - toBit));
            }

            return result;
        }

        private byte[] RotateRightBits(byte[] data, int shift)
        {
            if (data.Length == 0) return data;
            
            int bitLen = data.Length * 8;
            shift %= bitLen;
            if (shift == 0) return (byte[])data.Clone();

            byte[] result = new byte[data.Length];

            for (int i = 0; i < bitLen; i++)
            {
                int fromPos = (i - shift + bitLen) % bitLen;
                int fromByte = fromPos / 8;
                int fromBit = fromPos % 8;

                int toByte = i / 8;
                int toBit = i % 8;

                int bitVal = (data[fromByte] >> (7 - fromBit)) & 1;
                result[toByte] |= (byte)(bitVal << (7 - toBit));
            }

            return result;
        }

        private byte[] XOR(byte[] a, byte[] b)
        {
            if (a.Length != b.Length)
                throw new ArgumentException("Arrays must be of equal length");

            byte[] result = new byte[a.Length];
            for (int i = 0; i < a.Length; i++)
                result[i] = (byte)(a[i] ^ b[i]);
            return result;
        }

        private byte[] F(byte[] data, byte[] key)
        {
            if (data.Length != key.Length)
                throw new ArgumentException("Data and key must be of equal length");
            
            return XOR(data, key);
        }

        private byte[] EncryptRound(byte[] block, byte[] key)
        {
            int half = block.Length / 2;
            byte[] L = new byte[half];
            byte[] R = new byte[half];
            Array.Copy(block, 0, L, 0, half);
            Array.Copy(block, half, R, 0, half);

            byte[] fRes = F(R, key);
            byte[] newR = XOR(L, fRes);

            byte[] result = new byte[block.Length];
            Array.Copy(R, 0, result, 0, half);
            Array.Copy(newR, 0, result, half, half);

            return result;
        }

        private byte[] DecryptRound(byte[] block, byte[] key)
        {
            int half = block.Length / 2;
            byte[] L = new byte[half];
            byte[] R = new byte[half];
            Array.Copy(block, 0, L, 0, half);
            Array.Copy(block, half, R, 0, half);

            byte[] fRes = F(L, key);
            byte[] newR = XOR(R, fRes);

            byte[] result = new byte[block.Length];
            Array.Copy(newR, 0, result, 0, half);
            Array.Copy(L, 0, result, half, half);

            return result;
        }

        private byte[] CorrectKey(byte[] key, int length)
        {
            byte[] result = new byte[length];
            if (key.Length >= length)
                Array.Copy(key, result, length);
            else
            {
                Array.Copy(key, result, key.Length);
                for (int i = key.Length; i < length; i++)
                    result[i] = (byte)(i % 256); 
            }

            return result;
        }

        public byte[] Encrypt(byte[] data, byte[] key)
        {
            if (key == null || key.Length == 0)
                throw new ArgumentException("Key cannot be null or empty.");

            byte[] padded = AddPadding(data);
            int blockCount = padded.Length / BlockSize;
            byte[][] blocks = new byte[blockCount][];
            for (int i = 0; i < blockCount; i++)
            {
                blocks[i] = new byte[BlockSize];
                Array.Copy(padded, i * BlockSize, blocks[i], 0, BlockSize);
            }

            byte[] roundKey = CorrectKey(key, BlockSize / 2);

            for (int round = 0; round < Rounds; round++)
            {
                for (int i = 0; i < blockCount; i++)
                {
                    blocks[i] = EncryptRound(blocks[i], roundKey);
                }
                roundKey = RotateLeftBits(roundKey, ShiftKey);
            }

            byte[] encrypted = new byte[blockCount * BlockSize];
            for (int i = 0; i < blockCount; i++)
                Array.Copy(blocks[i], 0, encrypted, i * BlockSize, BlockSize);

            return encrypted;
        }

        public byte[] Decrypt(byte[] data, byte[] key)
        {
            if (key == null || key.Length == 0)
                throw new ArgumentException("Key cannot be null or empty.");

            if (data.Length % BlockSize != 0)
                throw new ArgumentException("Encrypted data is not aligned to block size.");

            int blockCount = data.Length / BlockSize;
            byte[][] blocks = new byte[blockCount][];
            for (int i = 0; i < blockCount; i++)
            {
                blocks[i] = new byte[BlockSize];
                Array.Copy(data, i * BlockSize, blocks[i], 0, BlockSize);
            }

            byte[] roundKey = CorrectKey(key, BlockSize / 2);
            roundKey = RotateLeftBits(roundKey, ShiftKey * Rounds); 

            for (int round = 0; round < Rounds; round++)
            {
                roundKey = RotateRightBits(roundKey, ShiftKey); 
                for (int i = 0; i < blockCount; i++)
                {
                    blocks[i] = DecryptRound(blocks[i], roundKey);
                }
            }

            byte[] decrypted = new byte[blockCount * BlockSize];
            for (int i = 0; i < blockCount; i++)
                Array.Copy(blocks[i], 0, decrypted, i * BlockSize, BlockSize);

            return RemovePadding(decrypted);
        }
    }
}