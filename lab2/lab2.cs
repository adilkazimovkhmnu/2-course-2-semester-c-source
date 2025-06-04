using System;
using Microsoft.Win32;
using System.Management;

class Program
{
    static void Main()
    {
        Console.WriteLine("Лабораторна робота №2. Робота з реєстром та WMI");
        Console.WriteLine("------------------------------------------------");
        
        Console.WriteLine("\n1. Демонстрація роботи з реєстром Windows\n");
        WorkWithRegistry();
        
        Console.WriteLine("\n2. Отримання інформації про систему через WMI\n");
        GetSystemInfoViaWMI();
        
        Console.WriteLine("\nРоботу завершено. Натисніть будь-яку клавішу для виходу...");
        Console.ReadKey();
    }
    
    static void WorkWithRegistry()
    {
        try
        {
            Console.WriteLine("Створюємо ключ у реєстрі...");
            RegistryKey key = Registry.CurrentUser.CreateSubKey("Software\\MyTestKey");
            key.SetValue("TestValue", "Приклад значення з лабораторної роботи");
            key.SetValue("NumberValue", 42);
            Console.WriteLine("Ключ та значення успішно створені.");
            
            Console.WriteLine("\nЧитаємо значення з реєстру:");
            RegistryKey readKey = Registry.CurrentUser.OpenSubKey("Software\\MyTestKey");
            Console.WriteLine("TestValue: " + readKey.GetValue("TestValue"));
            Console.WriteLine("NumberValue: " + readKey.GetValue("NumberValue"));
            readKey.Close();
            
            Console.WriteLine("\nВидаляємо тестовий ключ...");
            Registry.CurrentUser.DeleteSubKey("Software\\MyTestKey");
            Console.WriteLine("Ключ успішно видалено.");
        }
        catch (Exception ex)
        {
            Console.WriteLine("Помилка при роботі з реєстром: " + ex.Message);
        }
    }
    
    static void GetSystemInfoViaWMI()
    {
        try
        {
            Console.WriteLine("Отримуємо інформацію про процесор:");
            GetProcessorInfo();
            
            Console.WriteLine("\nОтримуємо інформацію про оперативну пам'ять:");
            GetMemoryInfo();
            
            Console.WriteLine("\nОтримуємо інформацію про жорсткі диски:");
            GetDiskInfo();
            
            Console.WriteLine("\nОтримуємо інформацію про відеокарту:");
            GetVideoControllerInfo();
            
            Console.WriteLine("\nОтримуємо інформацію про BIOS:");
            GetBiosInfo();
            
            Console.WriteLine("\nОтримуємо інформацію про логічні диски:");
            GetLogicalDisksInfo();
        }
        catch (Exception ex)
        {
            Console.WriteLine("Помилка при отриманні інформації через WMI: " + ex.Message);
        }
    }
    
    static void GetProcessorInfo()
    {
        ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT * FROM Win32_Processor");
        
        foreach (ManagementObject obj in searcher.Get())
        {
            Console.WriteLine($"Назва: {obj["Name"]}");
            Console.WriteLine($"Виробник: {obj["Manufacturer"]}");
            Console.WriteLine($"Архітектура: {GetArchitectureDescription(Convert.ToInt32(obj["Architecture"]))}");
            Console.WriteLine($"Кількість ядер: {obj["NumberOfCores"]}");
            Console.WriteLine($"Тактова частота: {Math.Round(Convert.ToDouble(obj["MaxClockSpeed"]) / 1000, 2)} GHz");
            Console.WriteLine($"Ідентифікатор: {obj["ProcessorId"]}");
        }
    }
    
    static string GetArchitectureDescription(int arch)
    {
        switch(arch)
        {
            case 0: return "x86";
            case 1: return "MIPS";
            case 2: return "Alpha";
            case 3: return "PowerPC";
            case 5: return "ARM";
            case 6: return "ia64";
            case 9: return "x64";
            default: return "Невідома архітектура";
        }
    }
    
    static void GetMemoryInfo()
    {
        ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT * FROM Win32_PhysicalMemory");
        
        double totalMemoryGB = 0;
        int moduleCount = 0;
        
        foreach (ManagementObject obj in searcher.Get())
        {
            moduleCount++;
            double capacityGB = Math.Round(Convert.ToDouble(obj["Capacity"]) / 1024 / 1024 / 1024, 2);
            totalMemoryGB += capacityGB;
            
            Console.WriteLine($"Модуль {moduleCount}:");
            Console.WriteLine($"  Виробник: {obj["Manufacturer"]}");
            Console.WriteLine($"  Об'єм: {capacityGB} ГБ");
            Console.WriteLine($"  Швидкість: {obj["Speed"]} МГц");
            Console.WriteLine($"  Банк: {obj["BankLabel"]}");
        }
        
        Console.WriteLine($"\nЗагальний об'єм оперативної пам'яті: {totalMemoryGB} ГБ");
    }
    
    static void GetDiskInfo()
    {
        ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT * FROM Win32_DiskDrive");
        
        foreach (ManagementObject obj in searcher.Get())
        {
            Console.WriteLine($"Модель: {obj["Model"]}");
            Console.WriteLine($"Інтерфейс: {obj["InterfaceType"]}");
            Console.WriteLine($"Серійний номер: {obj["SerialNumber"]?.ToString().Trim()}");
            Console.WriteLine($"Розмір: {Math.Round(Convert.ToDouble(obj["Size"]) / 1024 / 1024 / 1024, 2)} ГБ");
            Console.WriteLine($"Розділів: {obj["Partitions"]}");
            Console.WriteLine();
        }
    }
    
    static void GetVideoControllerInfo()
    {
        ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT * FROM Win32_VideoController");
        
        foreach (ManagementObject obj in searcher.Get())
        {
            Console.WriteLine($"Назва: {obj["Name"]}");
            Console.WriteLine($"Виробник: {obj["AdapterCompatibility"]}");
            Console.WriteLine($"Відеопроцесор: {obj["VideoProcessor"]}");
            Console.WriteLine($"Відеопам'ять: {Math.Round(Convert.ToDouble(obj["AdapterRAM"]) / 1024 / 1024, 2)} МБ");
            Console.WriteLine($"Роздільна здатність: {obj["CurrentHorizontalResolution"]}x{obj["CurrentVerticalResolution"]}");
            Console.WriteLine();
        }
    }
    
    static void GetBiosInfo()
    {
        ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT * FROM Win32_BIOS");
        
        foreach (ManagementObject obj in searcher.Get())
        {
            Console.WriteLine($"Виробник: {obj["Manufacturer"]}");
            Console.WriteLine($"Версія: {obj["Version"]}");
            Console.WriteLine($"Дата релізу: {obj["ReleaseDate"]}");
            Console.WriteLine($"Серійний номер: {obj["SerialNumber"]}");
            Console.WriteLine($"SMBIOS версія: {obj["SMBIOSMajorVersion"]}.{obj["SMBIOSMinorVersion"]}");
        }
    }
    
    static void GetLogicalDisksInfo()
    {
        ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT * FROM Win32_LogicalDisk");
        
        foreach (ManagementObject obj in searcher.Get())
        {
            string driveType = GetDriveTypeDescription(Convert.ToInt32(obj["DriveType"]));
            if (driveType != "Фіксований диск") continue;
            
            Console.WriteLine($"Диск: {obj["DeviceID"]}");
            Console.WriteLine($"  Тип: {driveType}");
            Console.WriteLine($"  Файлова система: {obj["FileSystem"]}");
            Console.WriteLine($"  Загальний об'єм: {Math.Round(Convert.ToDouble(obj["Size"]) / 1024 / 1024 / 1024, 2)} ГБ");
            Console.WriteLine($"  Вільний простір: {Math.Round(Convert.ToDouble(obj["FreeSpace"]) / 1024 / 1024 / 1024, 2)} ГБ");
        }
    }
    
    static string GetDriveTypeDescription(int type)
    {
        switch(type)
        {
            case 0: return "Невідомий";
            case 1: return "Немає кореневого каталогу";
            case 2: return "Знімний диск";
            case 3: return "Фіксований диск";
            case 4: return "Віддалений диск";
            case 5: return "CD-ROM";
            case 6: return "RAM-диск";
            default: return "Інший тип";
        }
    }
}