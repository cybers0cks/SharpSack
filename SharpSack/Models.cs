using System;
using System.IO;

namespace SharpSack
{
    internal class FileOutput
    {
        public string Name { get; set; }
        public string Type { get; set; }
        public string Size { get; set; }
        public string LastWriteDate { get; set; }
        public string LastWriteTime { get; set; }

        private const int maxNameLength = 60;

        public FileOutput(string file, string scope)
        {
            FileInfo fileInfo = new FileInfo(file);
            if (Directory.Exists(file))
            {
                Type = "DIR";
                Size = string.Empty;
            }
            else
            {
                Type = "";
                Size = fileInfo.Length.ToString();
            }

            Name = fileInfo.FullName.Replace(Path.GetFullPath(scope) + "\\", "");

            if (Name.Length > maxNameLength)
                Name = Name.Substring(0, maxNameLength - 3) + "...";


            DateTime lastWrite = File.GetLastWriteTime(file);

            LastWriteDate = lastWrite.ToShortDateString();
            LastWriteTime = lastWrite.ToShortTimeString();
        }

    }


    internal class Module
    {
        public string Name;
        public string Command;
        public string HelpText;
        public bool RequiresArgs;
        public string Tip;

        public Module(string name, string command, string helptext, bool requiresArgs = true, string tip = "")
        {
            Name = name;
            Command = command;
            HelpText = helptext;
            RequiresArgs = requiresArgs;
            Tip = tip;
        }
    }
}
