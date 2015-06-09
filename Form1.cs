using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Windows.Forms;
using AntiTamperEOF;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;

namespace AntiTamperEOF
{
    public partial class Form1 : Form
    {
        #region Declarations

        public string DirectoryName = "";
        public int ConstantKey;
        public int ConstantNum;
        public MethodDef Methoddecryption;
        public TypeDef Typedecryption;
        public MethodDef MethodeResource;
        public TypeDef TypeResource;
        public ModuleDefMD module;
        public int x;
        public int DeobedStringNumber;

        #endregion

        #region Designer

        public Form1()
        {
            InitializeComponent();
        }

        private void TextBox1DragEnter(object sender, DragEventArgs e)
        {
            if (e.Data.GetDataPresent(DataFormats.FileDrop))
            {
                e.Effect = DragDropEffects.Copy;
            }
            else
            {
                e.Effect = DragDropEffects.None;
            }
        }

        private void TextBox1DragDrop(object sender, DragEventArgs e)
        {
            try
            {
                Array array = (Array)e.Data.GetData(DataFormats.FileDrop);
                if (array != null)
                {
                    string text = array.GetValue(0).ToString();
                    int num = text.LastIndexOf(".", StringComparison.Ordinal);
                    if (num != -1)
                    {
                        string text2 = text.Substring(num);
                        text2 = text2.ToLower();
                        if (text2 == ".exe" || text2 == ".dll")
                        {
                            Activate();
                            textBox1.Text = text;
                            int num2 = text.LastIndexOf("\\", StringComparison.Ordinal);
                            if (num2 != -1)
                            {
                                DirectoryName = text.Remove(num2, text.Length - num2);
                            }
                            if (DirectoryName.Length == 2)
                            {
                                DirectoryName += "\\";
                            }
                        }
                    }
                }
            }
            catch
            {
            }
        }
        private void button3_Click(object sender, EventArgs e)
        {
            Environment.Exit(0);
        }

        private void button1_Click(object sender, EventArgs e)
        {
            label2.Text = "";
            OpenFileDialog openFileDialog = new OpenFileDialog();
            openFileDialog.Title = "Browse for target assembly";
            openFileDialog.InitialDirectory = "c:\\";
            if (DirectoryName != "")
            {
                openFileDialog.InitialDirectory = this.DirectoryName;
            }
            openFileDialog.Filter = "All files (*.exe,*.dll)|*.exe;*.dll";
            openFileDialog.FilterIndex = 2;
            openFileDialog.RestoreDirectory = true;
            if (openFileDialog.ShowDialog() == DialogResult.OK)
            {
                string fileName = openFileDialog.FileName;
                textBox1.Text = fileName;
                int num = fileName.LastIndexOf("\\", StringComparison.Ordinal);
                if (num != -1)
                {
                    DirectoryName = fileName.Remove(num, fileName.Length - num);
                }
                if (DirectoryName.Length == 2)
                {
                    DirectoryName += "\\";
                }
            }
        }
        #endregion

        private void button2_Click(object sender, EventArgs e)
        {
            ModuleDefMD mod = ModuleDefMD.Load(textBox1.Text);
            AddCall(mod);
            string text2 = Path.GetDirectoryName(textBox1.Text);
            if (!text2.EndsWith("\\"))
            {
                text2 += "\\";
            }
            string path = text2 + Path.GetFileNameWithoutExtension(textBox1.Text) + "_Tampered" +
                          Path.GetExtension(textBox1.Text);
            var opts = new ModuleWriterOptions(mod);
            opts.Logger = DummyLogger.NoThrowInstance;
            mod.Write(path, opts);
            label2.Text = "Successfully added Antitamper !";
            Md5(path);
        }

        public static void Md5(string filePath)
        {
            //We get the md5 as byte, of the target
            byte[] md5bytes = System.Security.Cryptography.MD5.Create().ComputeHash(System.IO.File.ReadAllBytes(filePath));
            //Let's use FileStream to edit the file's byte
            using (var stream = new FileStream(filePath, FileMode.Append))
            {
                //Append md5 in the end
                stream.Write(md5bytes, 0, md5bytes.Length); 
            }
        }


        public static void AddCall(ModuleDef module)
        {
            //We declare our Module, here we want to load the EOFAntitamp class, from AntiTamperEOF.exe
            ModuleDefMD typeModule = ModuleDefMD.Load(typeof(EOFAntitamp).Module);
            //We find or create the .cctor method in <Module>, aka GlobalType, if it doesn't exist yet
            MethodDef cctor = module.GlobalType.FindOrCreateStaticConstructor();
            //We declare EOFAntitamp as a TypeDef using it's Metadata token (needed)
            TypeDef typeDef = typeModule.ResolveTypeDef(MDToken.ToRID(typeof(EOFAntitamp).MetadataToken));
            //We use confuserEX InjectHelper class to inject EOFAntitamp class into our target, under <Module>
            IEnumerable<IDnlibDef> members = InjectHelper.Inject(typeDef, module.GlobalType, module);

            //We find the Initialize() Method in EOFAntitamp we just injected
			var init = (MethodDef)members.Single(method => method.Name == "Initialize");
            //We call this method using the Call Opcode
			cctor.Body.Instructions.Insert(0, Instruction.Create(OpCodes.Call, init));


            //We just have to remove .ctor method because otherwise it will
            //lead to Global constructor error (e.g [MD]: Error: Global item (field,method) must be Static. [token:0x06000002] / [MD]: Error: Global constructor. [token:0x06000002] )
            foreach (MethodDef md in module.GlobalType.Methods)
            {
                if (md.Name == ".ctor")
                {
                   module.GlobalType.Remove(md);
                    //Now we go out of this mess
                    break;
                }
            }          
        }

    }
   
}
