using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Dummy_Lib
{
    public class DummyMod100
    {
        public static int commandTab = 20;
        public static int instructionTab = 50;
        public static async Task dummy_mod(string[] args)
        {
            if (args[0] == "help")
            {
                string paddedString = "dummy.mod".PadRight(commandTab, ' ');
                string instruction = "DUMMY MOD".PadRight(instructionTab, ' ');
                Console.WriteLine($"{paddedString}{instruction}[NONE]");
                return;
            }
        }

        public static async Task test(string[] args)
        {
            if (args[0] == "help")
            {
                string paddedString = "test".PadRight(commandTab, ' ');
                string instruction = "DUMMY MOD 2".PadRight(instructionTab, ' ');
                Console.WriteLine($"{paddedString}{instruction}[TEST]");
                return;
            }

            Console.WriteLine(args[0]);
        }
    }
}
