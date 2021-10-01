using SimpleSniffer.BaseClass;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Windows.Threading;

namespace SimpleSniffer
{
    public partial class MainForm:Form
    {
        List<Monitor> monitorList = new List<Monitor>();

        List<Packet> pList = new List<Packet>();

        List<Packet> allList = new List<Packet>();

        delegate void refresh(Packet p);

        long totalLength = 0;

        long totalCount = 0;

        public MainForm()
        {
            InitializeComponent();
        }

        private void deactivateSearch()
        {
            filterCheckBox.Enabled = false;
            ipTextBox.Enabled = false;
            typeComboBox.Enabled = false;
            startButton.Enabled = false;
            filterButton.Enabled = false;
            allButton.Enabled = false;
        }

        private void activateSearch()
        {
            filterCheckBox.Enabled = true;
            ipTextBox.Enabled = true;
            typeComboBox.Enabled = true;
            startButton.Enabled = true;
            filterButton.Enabled = true;
            allButton.Enabled = true;
        }

        private void startRaking()
        {
            monitorList.Clear();
            IPAddress[] hosts = Dns.GetHostEntry(Dns.GetHostName()).AddressList;
            if (hosts == null || hosts.Length == 0)
            {
                MessageBox.Show("No hosts detected, please check your network!");
            }
            for (int i = 0; i < hosts.Length; i++)
            {
                Monitor monitor = new Monitor(hosts[i]);
                monitor.newPacketEventHandler += new Monitor.NewPacketEventHandler(onNewPacket);
                monitorList.Add(monitor);
            }
            foreach(Monitor monitor in monitorList)
            {
                monitor.start();
            }
        }

        private void onNewPacket(Monitor monitor, Packet p)
        {
            
            this.Invoke(new refresh(onRefresh), p);
        }

        private void onRefresh(Packet p)
        {
            if (this.filterCheckBox.Checked)
            {
                string[] conditions = getFilterCondition();
                if (isIPOkay(p, conditions[0]) && isPORTOkay(p, conditions[1])
                    && (conditions[2] == "" || conditions[2] == p.Type))
                {
                    addAndUpdatePackets(p);
                }
            }
            else
            {
                addAndUpdatePackets(p);
            }
            if (totalLength < 10 * 1024)
            {
                this.hintLabel.Text = string.Format("Packets received {0}  Total length： [{1} bytes]", totalCount, totalLength);
            }
            else if (totalLength < 10 * 1024 * 1024)
            {
                this.hintLabel.Text = string.Format("Packets received {0}  Total length： [{1} KB]", totalCount, totalLength / 1024);
            }
            else if (totalLength < 1024 * 1024 * 1024)
            {
                this.hintLabel.Text = string.Format("Packets received {0}  Total length： [{1} MB]", totalCount, totalLength / (1024 * 1024));
            }
            else if(totalLength < (long)1024 * 1024 * 1024 * 2)
            {
                this.hintLabel.Text = string.Format("Packets received {0}  Total length： [{1} GB]", totalCount, totalLength / (1024 * 1024 * 1024));
            }
            else
            {
                totalCount = 0;
                totalLength = 0;
                this.listView.Items.Clear();
                this.pList.Clear();
                this.allList.Clear();
                this.hintLabel.Text = string.Format("Packets received {0}  Total length： [{1} bytes]", 0, 0);
            }
        }

        private bool isIPOkay(Packet p, string ip)
        {
            return ip == "" || p.Src_IP == ip || p.Des_IP == ip;
        }

        private bool isPORTOkay(Packet p, string port)
        {
            return port == "" || p.Src_PORT == port || p.Des_PORT == port;
        }

        private void addAndUpdatePackets(Packet p)
        {
            totalCount++;
            totalLength += p.TotalLength;
            allList.Add(p);
            pList.Add(p);
            this.listView.Items.Add(new ListViewItem(new string[] { p.Src_IP, p.Src_PORT,p.Des_IP, p.Des_PORT,
                        p.Type, p.Time, p.TotalLength.ToString(), p.getCharString()}));
            this.listView.EnsureVisible(listView.Items.Count > 5? listView.Items.Count - 10:listView.Items.Count);
        }

        private void stopReceiving()
        {
            foreach (Monitor monitor in monitorList)
            {
                monitor.stop();
            }
        }

        private void clearDetail()
        {
            this.charTextBox.Text = "";
            this.hexTextBox.Text = "";
        }

        private void startButton_Click(object sender, EventArgs e)
        {
            clearDetail();
            deactivateSearch();
            startRaking();
        }

        private void stopButton_Click(object sender, EventArgs e)
        {
            clearDetail();
            activateSearch();
            stopReceiving();
        }

        private void clearButton_Click(object sender, EventArgs e)
        {
            this.listView.Items.Clear();
            pList.Clear();
            clearDetail();
        }

        private void clearButton_DoubleClick(object sender, System.EventArgs e)
        {
            totalCount = 0;
            totalLength = 0;
            clearDetail();
            this.listView.Items.Clear();
            this.pList.Clear();
            this.allList.Clear();
            this.hintLabel.Text = string.Format("Packets received {0}  Total length： [{1} bytes]", 0, 0);
        }

        private void allButton_Click(object sender, EventArgs e)
        {
            this.listView.Items.Clear();
            pList.Clear();
            Packet p;
            for (int i = 0; i < allList.Count; i++)
            {
                p = allList[i];
                pList.Add(p);
                this.listView.Items.Add(new ListViewItem(new string[] { p.Src_IP, p.Src_PORT,p.Des_IP, p.Des_PORT,
                        p.Type, p.Time, p.TotalLength.ToString(), p.getCharString()}));
            }
            clearDetail();
        }

        private void ipTextBox_GotFocus(object sender, System.EventArgs e)
        {
            ipTextBox.ForeColor = Color.Black;
            ipTextBox.Text = "";
            ipTextBox.GotFocus -= ipTextBox_GotFocus;
        }

        private void listView_SelectedIndexChanged(object sender, EventArgs e)
        {
            ListView listView = sender as ListView;
            if (listView.SelectedItems != null && listView.SelectedItems.Count != 0)
            {
                Packet p = pList[listView.SelectedItems[0].Index];
                this.hexTextBox.Text = p.getHexString();
                this.charTextBox.Text = p.getCharString();
            }
        }

        private void filterCheckBox_CheckedChanged(object sender, EventArgs e)
        {
            if(this.filterCheckBox.Checked && this.ipTextBox.ForeColor != Color.Black)
            {
                this.ipTextBox.Text = "";
                this.ipTextBox.ForeColor = Color.Black;
            }
        }

        private void MainForm_Load(object sender, EventArgs e)
        {
            this.charTextBox.OtherRichTextBox = this.hexTextBox;
        }

        private void MainFrom_FormClosing(object sender, FormClosingEventArgs e)
        {
            DialogResult result = MessageBox.Show("Are you sure to close the lovely App!", "Little Hint", MessageBoxButtons.OKCancel, MessageBoxIcon.Information);
            if (result == DialogResult.OK)
            {
                e.Cancel = false;  //close it;
            }
            else
            {
                e.Cancel = true;
            }
        }

        private int getCharCount(string s, char c)
        {
            int count = 0;
            for (int i = 0; i < s.Length; i++)
            {
                if(s[i] == c)
                {
                    count++;
                }
            }
            return count;
        }

        private List<int> getStringIndex(string s, string s0)
        {
            List<int> countList = new List<int>();
            int index = 0;
            while(s.Contains(s0))
            {
                index = s.IndexOf(s0);
                s = s.Substring(0, index + s0.Length);
                countList.Add(index);
            }
            for (int i = 1; i < countList.Count; i++)
            {
                countList[i] += (countList[i - 1] + s0.Length);
            }
            return countList;
        }

        private void charTextBox_SelectionChanged(object sender, System.EventArgs e)
        {
            string charString = this.charTextBox.Text;
            string selectedString = this.charTextBox.SelectedText;
            int selectedLength = selectedString.Length;

            int start0 = this.charTextBox.SelectionStart - selectedLength;
            int start1 = this.charTextBox.SelectionStart;

            int index = 0;
            if(start0 > -1 && charString.Substring(start0, selectedLength).Equals(selectedString))
            {
                index = start0;
            }
            else
            {
                index = start1;
            }

            string tmpString = this.charTextBox.Text.Substring(0, index);
            int spaceCount = getCharCount(tmpString, '\n');

            int start = tmpString.Length * 3 - 2 * spaceCount;
            int selectedHexLength = this.charTextBox.SelectedText.Length * 3 - 2 * getCharCount(this.charTextBox.SelectedText, '\n');
            if (selectedHexLength > 0)
            {
                this.hexTextBox.SelectionStart = 0;
                this.hexTextBox.SelectionLength = this.hexTextBox.Text.Length;
                this.hexTextBox.SelectionBackColor = Color.White;

                this.hexTextBox.SelectionStart = start;
                this.hexTextBox.SelectionLength = selectedHexLength;
                this.hexTextBox.SelectionBackColor = Color.Red;
            }
        }

        private void charTextBox_MouseClick(object sender, MouseEventArgs e)
        {
            if(this.charTextBox.SelectedText.Length == 0)
            {
                this.hexTextBox.SelectionStart = 0;
                this.hexTextBox.SelectionLength = this.hexTextBox.Text.Length;
                this.hexTextBox.SelectionBackColor = Color.White;
            }
        }

        private void filterButton_Click(object sender, EventArgs e)
        {
            if (this.listView.Items.Count < 1)
            {
                MessageBox.Show("Please sniff or show all the sniffed packets first！");
            }
            showIPPackets(getFilterCondition());
            clearDetail();
        }

        private string[] getFilterCondition()
        {
            string[] conditions = { "", "", "" };
            string tmpString = this.ipTextBox.Text;
            int port = 0;
            if (this.typeComboBox.SelectedIndex > -1)
                conditions[2] = this.typeComboBox.SelectedItem.ToString();
            if (tmpString.Contains('/') || tmpString.Contains(':'))
            {
                string[] arr = { null, null };
                if (tmpString.Contains('/'))
                    arr = tmpString.Split(new char[] { '/' });
                else
                    arr = tmpString.Split(new char[] { ':' });
                conditions[0] = arr[0];
                conditions[1] = arr[1];
            }
            else if (int.TryParse(tmpString, out port))
                conditions[1] = port.ToString();
            else
                conditions[0] = tmpString;
            return conditions;
        }

        private void showIPPackets(string[] conditions)
        {
            string ipString = conditions[0];
            string port = conditions[1];
            string type = conditions[2];
            Packet p;
            this.listView.Items.Clear();
            pList.Clear();
            for(int i = 0; i < allList.Count; i++)
            {
                p = allList[i];
                if (isIPOkay(p, conditions[0]) && isPORTOkay(p, conditions[1])
                    && (conditions[2] == "" || conditions[2] == p.Type))
                {
                    pList.Add(p);
                    this.listView.Items.Add(new ListViewItem(new string[] { p.Src_IP, p.Src_PORT,p.Des_IP, p.Des_PORT,
                        p.Type, p.Time, p.TotalLength.ToString(), p.getCharString()}));
                }
            }
        }

        private void listView_ColumnWidthChanging(object sender, ColumnWidthChangingEventArgs e)
        {
            e.Cancel = true;
            e.NewWidth = this.listView.Columns[e.ColumnIndex].Width;
        }
    }
}
