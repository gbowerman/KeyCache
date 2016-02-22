/* KeyCache - password storage desktop app for Windows, based on AES-256 encryption
 https://github.com/gbowerman/KeyCache
 Copyright (c) 2016, Guy Bowerman 
 License: MIT
 Contact: guybo@outlook.com
 To do:
   - Add tooltips
   - Add "Save As" option
   - support newlines in Notes section
*/
using System;
using System.Collections;
using System.Deployment.Application;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Windows;
using System.Windows.Controls;

namespace KeyCache
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        // raw and filtered key lists
        ArrayList keyCacheList = new ArrayList();
        ArrayList filterList = new ArrayList();

        // booleans representing program state
        bool unsavedChanges = false;
        bool usingFilter = false;
        bool successfulDecrypt = false;
        bool changingPassPhrase = false;

        private string passPhrase = "";
        private string tempPassPhrase = null;
        private string fileName = null;

        // memory buffers used for encryption
        private byte[] cryptBuffer = null;
        private byte[] frontLockHash = null;

        public MainWindow()
        {
            InitializeComponent();
            form1.Title = "Key Cache " + getRunningVersion();

            if (Properties.Settings.Default.lastFile != null && Properties.Settings.Default.lastFile.Length > 0)
            {
                fileName = Properties.Settings.Default.lastFile;
                if (!File.Exists(fileName))
                {
                    fileName = null;
                }
            }
            else
            {
                MessageBox.Show("If you're running KeyCache for the first time, start by entering a password.\n" +
                                "Then add some records.\nYou will be prompted to create a new file when you close the app.\n" +
                                "Alternatively, after setting a password you can open an existing encrypted file.", "Welcome", 
                                MessageBoxButton.OK, MessageBoxImage.Information);
            }
            
            // the list that holds the information
            LsView.ItemsSource = keyCacheList;
            passPhraseBox.Focus();
        }

        /// <summary>
        /// Display the highlighted fields
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void ListView_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (LsView.SelectedIndex != -1)
            {
                Keys key = (Keys)LsView.SelectedItem;
                nameBox.Text = key.Name;
                idBox.Text = key.ID;
                passwordBox.Text = key.Password;
                noteBox.Text = key.Notes;
            }
        }

        /// <summary>
        /// Adds a new record to the list
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void addButton_Click(object sender, RoutedEventArgs e)
        {
            if (nameBox.Text.Length == 0)
            {
                MessageBox.Show("All records must have a name", "No name", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            // check for duplicates
            foreach (Keys key in keyCacheList)
            {
                if (key.Name.Equals(nameBox.Text))
                {
                    MessageBox.Show("Matching record already exists, use a new Name", "Duplicate record", MessageBoxButton.OK, MessageBoxImage.Stop);
                    nameBox.Text = "";
                    nameBox.Focus();
                    return;
                }
            }
          
           keyCacheList.Add(new Keys(nameBox.Text, idBox.Text, passwordBox.Text, noteBox.Text));
           unsavedChanges = true;

            // if filterList was active, reset it after an add
           if (usingFilter == true)
           {
               resetFilter();
           }
           LsView.Items.Refresh();

           // highlight last item
           LsView.SelectedIndex = LsView.Items.Count - 1;

           // move to last item
           LsView.ScrollIntoView(LsView.SelectedItem);
        }

        /// <summary>
        /// resets filter back to blank, to be used after add/modify/delete
        /// </summary>
        private void resetFilter()
        {
            filterBox.Text = "";
            LsView.ItemsSource = keyCacheList;
            usingFilter = false;
        }

        private void Window_Closing(object sender, System.ComponentModel.CancelEventArgs e)
        {
            if (unsavedChanges == true)
            {
                // auto-save changes
                // save as TSV before encrypting
                saveFile();
            }
        }

        private void saveFile()
        {
            string textBuffer = "";

            // loop through list assembling text file
            foreach (Keys key in keyCacheList)
            {
                string line = key.Name + "\t" + key.ID + "\t" + key.Password + "\t" + key.Notes + "\r\n";
                //MessageBox.Show("Line: " + line);
                textBuffer += line;
            }

            // now we have an unencrypted text file, apply encryption and save file
            if (passPhrase.Length < 1)
            {
                // to do: change this to enter a passphrase request
                var result = MessageBox.Show("No pass phrase set, do you want to save as plaintext?", 
                    "No pass phrase", MessageBoxButton.YesNo, MessageBoxImage.Question);
                if (result == MessageBoxResult.No)
                {
                    MessageBox.Show("Exiting program without saving data", "Data not saved", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }
                return; // saving as plaintext not currently supported
            }
            
            // if filename is not set then we need to create one
            if (fileName == null)
            {
                saveFileAs(textBuffer);
            }
            else
            {
                // encrypt text
                if (frontLockHash == null)
                {
                    frontLockHash = getFrontLockSha(passPhrase, Path.GetFileName(fileName));
                }
                cryptBuffer = AESEncryptString(textBuffer, passPhrase, frontLockHash);
                addSHAandWriteFile();
            }
        }

        private void saveFileAs(string textBuffer)
        {
            Microsoft.Win32.SaveFileDialog saveFd = new Microsoft.Win32.SaveFileDialog();
            saveFd.DefaultExt = ".text"; // Default file extension
            saveFd.Filter = "Text Files|*.txt|All Files|*.*";
            saveFd.Title = "Save Encrypted File";

            // Show save file dialog box
            Nullable<bool> result = saveFd.ShowDialog();

            // Process save file dialog box results
            if (result == true)
            {
                // Save document
                fileName = saveFd.FileName;
            }
            else return;

            // save a record of the last file that was saved
            Properties.Settings.Default.lastFile = fileName;
            Properties.Settings.Default.Save();

            // encrypt text
            frontLockHash = getFrontLockSha(passPhrase, Path.GetFileName(fileName));
            cryptBuffer = AESEncryptString(textBuffer, passPhrase, frontLockHash);
            
            if (addSHAandWriteFile() == true)
            {
                MessageBox.Show("Encrypted file " + fileName + " saved.", "File Saved", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            unsavedChanges = false;
        }

        /// <summary>
        /// Before writing the file to save, add a hash of pass phrase and filename
        /// - the hash will be use to verify pass phrase when reading file in
        /// </summary>
        /// <returns></returns>
        private bool addSHAandWriteFile()
        {
            // now combine the salt and fileBuffer
            byte[] combinedBuffer = null;
            using (var s = new MemoryStream())
            {
                s.Write(frontLockHash, 0, frontLockHash.Length);
                s.Write(cryptBuffer, 0, cryptBuffer.Length);
                combinedBuffer = s.ToArray();
            }

            try
            {
                File.WriteAllBytes(fileName, combinedBuffer);
                return true;
            }
            catch (Exception ex)
            {
                MessageBox.Show("Saving file " + fileName + " failed:" + ex.Message, "Save failed", MessageBoxButton.OK, MessageBoxImage.Error);
                return false;
            }
        }

        private byte[] getFrontLockSha(string str1, string str2)
        {
            string saltString = str1 + str2;

            // convert text to bytes to get hash
            ASCIIEncoding AE = new ASCIIEncoding();
            
             byte[] saltBuffer = AE.GetBytes(saltString);
             return GetSHA512(saltBuffer);
        }

        private byte[] AESEncryptString(string clearText, string passText, byte[] saltBytes)
        {
            byte[] clearBytes = Encoding.UTF8.GetBytes(clearText);
            byte[] passBytes = Encoding.UTF8.GetBytes(passText);

            // set the global value, which will be used by the Save button
            return AESEncryptBytes(clearBytes, passBytes, saltBytes);
        }

        private byte[] AESEncryptBytes(byte[] clearBytes, byte[] passBytes, byte[] saltBytes)
        {
            byte[] encryptedBytes = null;

            // create a key from the password and salt, use 32K iterations
            var key = new Rfc2898DeriveBytes(passBytes, saltBytes, 32768);

            // create an AES object
            using (Aes aes = new AesManaged())
            {
                // set the key size to 256
                aes.KeySize = 256;
                aes.Key = key.GetBytes(aes.KeySize / 8);
                aes.IV = key.GetBytes(aes.BlockSize / 8);

                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(clearBytes, 0, clearBytes.Length);
                        cs.Close();
                    }
                    encryptedBytes = ms.ToArray();
                }
            }
            return encryptedBytes;
        }

        private string AESDecryptBytes(byte[] cryptBytes, string passPhrase, byte[] saltBytes)
        {
            byte[] clearBytes = null;
            byte[] passBytes = Encoding.UTF8.GetBytes(passPhrase);

            // create a key from the password and salt, use 32K iterations
            var key = new Rfc2898DeriveBytes(passBytes, saltBytes, 32768);

            using (Aes aes = new AesManaged())
            {
                // set the key size to 256
                aes.KeySize = 256;
                aes.Key = key.GetBytes(aes.KeySize / 8);
                aes.IV = key.GetBytes(aes.BlockSize / 8);

                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(cryptBytes, 0, cryptBytes.Length);
                        cs.Close();
                    }
                    clearBytes = ms.ToArray();
                }
            }
            return Encoding.UTF8.GetString(clearBytes);
        }

        private byte[] GetSHA512(byte[] plainBuf)
        {
            byte[] hash;
            using (SHA512Managed hashVal = new SHA512Managed())
            {
                hash = hashVal.ComputeHash(plainBuf);
            }
            return hash;
        }

        /// <summary>
        /// Delete the highlighted record
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void deleteButton_Click(object sender, RoutedEventArgs e)
        {
            if (LsView.SelectedIndex == -1)
            {
                MessageBox.Show("You need to highlight a record before deleting it.", "No record highlighted", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }
            
            // loop through keyCacheList to find the matching index and delete it
            int index = 0;
            bool matchFound = false;
            foreach (Keys key in keyCacheList)
            {
                if (key.Name.Equals(nameBox.Text))
                {
                    matchFound = true;
                    break;
                }
                index++;
            }

            if (matchFound == true)
            {
                keyCacheList.RemoveAt(index);
                unsavedChanges = true;
            }
            else
            {
                MessageBox.Show("Matching record not found - did you change the Name?", "Not found", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            if (usingFilter)
            {
                resetFilter();
            }
            LsView.Items.Refresh();

            // highlight previous item
            if (index > 0) LsView.SelectedIndex = index - 1;
            else if (LsView.Items.Count > 0)
            {
                LsView.SelectedIndex = 0;
            }
        }

        private void modifyButton_Click(object sender, RoutedEventArgs e)
        {
            if (LsView.SelectedIndex == -1)
            {
                MessageBox.Show("You need to highlight a record to modify it.", "No record highlighted", MessageBoxButton.OK, MessageBoxImage.Error);
            }

            // find the matching keycache list record and update
            foreach (Keys key in keyCacheList)
            {
                if (key.Name.Equals(nameBox.Text))
                {
                    key.Name = nameBox.Text;
                    key.ID = idBox.Text;
                    key.Password = passwordBox.Text;
                    key.Notes = noteBox.Text;
                    break;
                }  
            }
            // if using filter, reset it after a modify
            if (usingFilter == true)
            {
                resetFilter();
            }
            unsavedChanges = true;
            LsView.Items.Refresh();
        }

        /// <summary>
        /// Open a dialog to read in a new file
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void openButton_Click(object sender, RoutedEventArgs e)
        {
            if (passPhrase.Length < 1)
            {
                MessageBox.Show("Pass phrase not set, opening file unencrypted", "No Pass Phrase", MessageBoxButton.OK, MessageBoxImage.Warning);
            }

            Microsoft.Win32.OpenFileDialog dlg = new Microsoft.Win32.OpenFileDialog(); 
            // dlg.Filter = "txt files (*.txt)|*.txt|All files (*.*)|*.*" ;
            if (dlg.ShowDialog() == true)
            {
                fileName = dlg.FileName;
                LoadFile();
            }
        }

        /// <summary>
        /// LoadFile - Reads encrypted file into memory
        /// - validates password against frontdoor hash
        /// - decryptes file to text
        /// - populates record list from text buffer
        /// </summary>
        private void LoadFile()
        {
            // first validate pass phrase against front lock hash (first 64 bytes)
            frontLockHash = getFrontLockSha(passPhrase, Path.GetFileName(fileName));

            // read file into memory
            byte[] combinedBuffer = File.ReadAllBytes(fileName);
            
            // compare with first 64 bytes of fileBuffer
            byte[] compareHash = new byte[64];
            Buffer.BlockCopy(combinedBuffer, 0, compareHash, 0, 64);
            if (StructuralComparisons.StructuralEqualityComparer.Equals(frontLockHash, compareHash) == false)
            {
                MessageBox.Show("Pass phrase incorrect. Try again", "Wrong pass phrase", MessageBoxButton.OK, MessageBoxImage.Exclamation);
                keyCacheList.Clear();
                return;
            }

            // pass phrase is validated - now copy the remaining bytes to fileBuffer
            int fileBufferLength = combinedBuffer.Length - 64; 
            cryptBuffer = new byte[fileBufferLength];
            Buffer.BlockCopy(combinedBuffer, 64, cryptBuffer, 0, fileBufferLength);
            
            try
            {

                string textBuffer = AESDecryptBytes(cryptBuffer, passPhrase, frontLockHash);
           
                // now load text buffer into keyCacheList
                string[] pswdLines = textBuffer.Split(new string[] { "\r\n" }, StringSplitOptions.RemoveEmptyEntries);

                // loop through pswdLines[] and load into keycache
                foreach (string line in pswdLines)
                {
                    //MessageBox.Show("Reading line: " + line);
                    string[] keyParts = line.Split('\t');
                    keyCacheList.Add(new Keys(keyParts[0], keyParts[1], keyParts[2], keyParts[3]));
                }

            }
            catch (Exception ex) // since pass phrase is already validated, getting an exception here is unexpected
            {
                MessageBox.Show("Error decrypting: " + ex.Message, "Decryption exception", MessageBoxButton.OK, MessageBoxImage.Exclamation);
                keyCacheList.Clear();
                cryptBuffer = null;
                return;
            }

            // sort
            keyCacheList.Sort(new CustomComparer());
            successfulDecrypt = true;

            LsView.Items.Refresh();
            filterBox.Focus();

            unsavedChanges = false; // this won't be true until a subsequent textbox change

            // save a record of the last file opened
            Properties.Settings.Default.lastFile = fileName;
            Properties.Settings.Default.Save();
        }

        /// <summary>
        /// User types in a new password. Either:
        /// - typing in password for first time before any file loaded
        /// - retyping a password after an authentication failure
        /// - changing password
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void passPhraseBox_KeyUp(object sender, System.Windows.Input.KeyEventArgs e)
        {
            // set password if user presses Enter
            if (e.Key == System.Windows.Input.Key.Return)
            {
                if (passPhraseBox.Password.Length < 1)
                {
                    MessageBox.Show("No pass phrase set.", "Missing pass phrase", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }
                if (changingPassPhrase == false)
                {
                    // if file not loaded, load the default file if it exists
                    if (successfulDecrypt == false && fileName != null && File.Exists(fileName))
                    {
                        passPhrase = passPhraseBox.Password;
                        keyCacheList.Clear();
                        LoadFile();
                    }
                    else // password should be entered again to verify change (or new password)
                    {
                        MessageBox.Show("Please enter password again to verify.", "Setting password", MessageBoxButton.OK, MessageBoxImage.Asterisk);
                        changingPassPhrase = true;
                        tempPassPhrase = passPhraseBox.Password;
                        passPhraseBox.Password = "";
                        passPhraseBox.Focus();
                        return;
                    }
                }
                else // changingPassPhrase = true
                {
                    if (passPhraseBox.Password.Equals(tempPassPhrase))
                    {
                        unsavedChanges = true; // force a re-encrypt upon exit
                        frontLockHash = null;  // force recalculation of the front lock hash
                        changingPassPhrase = false;
                        passPhrase = tempPassPhrase;
                        MessageBox.Show("Pass phrase set.", "Success", MessageBoxButton.OK, MessageBoxImage.Information);
                        filterBox.Focus();
                    }
                    else
                    {
                        MessageBox.Show("Password mismatch. Please try again", "Setting password", MessageBoxButton.OK, MessageBoxImage.Warning);
                        passPhraseBox.Password = "";
                        passPhraseBox.Focus();
                        changingPassPhrase = false;
                        return;
                    }
                }
            }
        }

        /// <summary>
        /// When a character is typed, display records which match the filter string
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void filterBox_KeyUp(object sender, System.Windows.Input.KeyEventArgs e)
        {
            // start with an empty keycachelist
            // loop through original list adding matching records

            // if filterBox is empty go back to using regular list
            if (filterBox.Text.Length < 1)
            {
                usingFilter = false;
                LsView.ItemsSource = keyCacheList;
                return;
            }

            string filterStr = filterBox.Text.ToLower();
            filterList.Clear();
            foreach (Keys key in keyCacheList)
            {
                if (key.Name.ToLower().Contains(filterStr))
                {
                    filterList.Add(new Keys(key.Name, key.ID, key.Password, key.Notes));
                }
            }
            // change LsView input to new list 
            LsView.ItemsSource = filterList;
            LsView.Items.Refresh();

            // then modify/delete/add/save operations will have to reconcile the list
            usingFilter = true;
        }

        /// <summary>
        /// Standard method to get and display version
        /// </summary>
        /// <returns></returns>
        private Version getRunningVersion()
        {
            try
            {
                return ApplicationDeployment.CurrentDeployment.CurrentVersion;
            }
            catch (Exception)
            {
                return Assembly.GetExecutingAssembly().GetName().Version;
            }

        }

    }
}

/// <summary>
/// keys data store structure for password records
/// </summary>
public class Keys
{
    public Keys(string keyName, string keyID, string keyPassword, string keyNotes)
    {
        this.Name = keyName;
        this.ID = keyID;
        this.Password = keyPassword;
        this.Notes = keyNotes;
    }

    private string name;
    public string Name
    {
        get { return name; }
        set { name = value; }
    }

    private string id;
    public string ID
    {
        get { return id; }
        set { id = value; }
    }

    private string password;
    public string Password
    {
        get { return password; }
        set { password = value; }
    }

    private string notes;
    public string Notes
    {
        get { return notes; }
        set { notes = value; }
    }
}

public class CustomComparer : IComparer
{
    Comparer _comparer = new Comparer(System.Globalization.CultureInfo.CurrentCulture);

    public int Compare(object x, object y)
    {
        // Convert string comparisons to int
        Keys key1 = (Keys)x;
        Keys key2 = (Keys)y;
        return _comparer.Compare(key1.Name, key2.Name);
    }
}
