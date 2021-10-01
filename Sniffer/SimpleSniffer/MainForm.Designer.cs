using SimpleSniffer.BaseClass;
using System.IO;
using System.Reflection;
using System.Windows.Forms;
namespace SimpleSniffer
{
    partial class MainForm
    {
        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            this.components = new System.ComponentModel.Container();
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(MainForm));
            this.startButton = new System.Windows.Forms.Button();
            this.stopButton = new System.Windows.Forms.Button();
            this.toolTip1 = new System.Windows.Forms.ToolTip(this.components);
            this.hintLabel = new System.Windows.Forms.Label();
            this.clearButton = new SimpleSniffer.BaseClass.MyButton();
            this.packetBindingSource = new System.Windows.Forms.BindingSource(this.components);
            this.header = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.typeComboBox = new System.Windows.Forms.ComboBox();
            this.allButton = new System.Windows.Forms.Button();
            this.filterButton = new System.Windows.Forms.Button();
            this.toolTip2 = new System.Windows.Forms.ToolTip(this.components);
            this.charTextBox = new SimpleSniffer.BaseClass.MyRichTextBox();
            this.hexTextBox = new SimpleSniffer.BaseClass.MyRichTextBox();
            this.toolTip3 = new System.Windows.Forms.ToolTip(this.components);
            this.columnHeader1 = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.columnHeader2 = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.columnHeader3 = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.columnHeader4 = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.columnHeader5 = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.columnHeader6 = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.columnHeader7 = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.columnHeader8 = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.listView = new System.Windows.Forms.ListView();
            this.ipTextBox = new System.Windows.Forms.TextBox();
            this.filterCheckBox = new System.Windows.Forms.CheckBox();
            ((System.ComponentModel.ISupportInitialize)(this.packetBindingSource)).BeginInit();
            this.SuspendLayout();
            // 
            // startButton
            // 
            this.startButton.Font = new System.Drawing.Font("Times New Roman", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.startButton.Location = new System.Drawing.Point(661, 11);
            this.startButton.Margin = new System.Windows.Forms.Padding(4);
            this.startButton.Name = "startButton";
            this.startButton.Size = new System.Drawing.Size(93, 40);
            this.startButton.TabIndex = 1;
            this.startButton.Text = "Start";
            this.startButton.UseVisualStyleBackColor = true;
            this.startButton.Click += new System.EventHandler(this.startButton_Click);
            // 
            // stopButton
            // 
            this.stopButton.Font = new System.Drawing.Font("Times New Roman", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.stopButton.Location = new System.Drawing.Point(775, 11);
            this.stopButton.Margin = new System.Windows.Forms.Padding(4);
            this.stopButton.Name = "stopButton";
            this.stopButton.Size = new System.Drawing.Size(93, 40);
            this.stopButton.TabIndex = 2;
            this.stopButton.Text = "Stop";
            this.stopButton.UseVisualStyleBackColor = true;
            this.stopButton.Click += new System.EventHandler(this.stopButton_Click);
            // 
            // hintLabel
            // 
            this.hintLabel.AutoSize = true;
            this.hintLabel.Font = new System.Drawing.Font("Times New Roman", 10.5F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.hintLabel.Location = new System.Drawing.Point(1, 641);
            this.hintLabel.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            this.hintLabel.Name = "hintLabel";
            this.hintLabel.Size = new System.Drawing.Size(319, 20);
            this.hintLabel.TabIndex = 4;
            this.hintLabel.Text = "Packets received: 0  Total length: [0 Bytes]";
            // 
            // clearButton
            // 
            this.clearButton.Font = new System.Drawing.Font("Times New Roman", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.clearButton.Location = new System.Drawing.Point(888, 11);
            this.clearButton.Margin = new System.Windows.Forms.Padding(4);
            this.clearButton.Name = "clearButton";
            this.clearButton.Size = new System.Drawing.Size(93, 40);
            this.clearButton.TabIndex = 5;
            this.clearButton.Text = "Clear";
            this.toolTip3.SetToolTip(this.clearButton, "One click, clear all the list; double click, clear all the sniffed packets");
            this.clearButton.UseVisualStyleBackColor = true;
            this.clearButton.Click += new System.EventHandler(this.clearButton_Click);
            // 
            // typeComboBox
            // 
            this.typeComboBox.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.typeComboBox.Font = new System.Drawing.Font("Times New Roman", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.typeComboBox.FormattingEnabled = true;
            this.typeComboBox.Items.AddRange(new object[] {
            "",
            "TCP",
            "UDP",
            "GGP",
            "ICMP",
            "IDP",
            "IGMP",
            "IP",
            "ND",
            "PUP",
            "OTHERS"});
            this.typeComboBox.Location = new System.Drawing.Point(373, 13);
            this.typeComboBox.Margin = new System.Windows.Forms.Padding(0);
            this.typeComboBox.Name = "typeComboBox";
            this.typeComboBox.Size = new System.Drawing.Size(136, 30);
            this.typeComboBox.TabIndex = 7;
            // 
            // allButton
            // 
            this.allButton.Font = new System.Drawing.Font("Times New Roman", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.allButton.Location = new System.Drawing.Point(987, 11);
            this.allButton.Margin = new System.Windows.Forms.Padding(4);
            this.allButton.Name = "allButton";
            this.allButton.Size = new System.Drawing.Size(113, 40);
            this.allButton.TabIndex = 10;
            this.allButton.Text = "AllSniffed";
            this.allButton.UseVisualStyleBackColor = true;
            this.allButton.Click += new System.EventHandler(this.allButton_Click);
            // 
            // filterButton
            // 
            this.filterButton.Font = new System.Drawing.Font("Times New Roman", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.filterButton.Location = new System.Drawing.Point(549, 11);
            this.filterButton.Margin = new System.Windows.Forms.Padding(4);
            this.filterButton.Name = "filterButton";
            this.filterButton.Size = new System.Drawing.Size(93, 40);
            this.filterButton.TabIndex = 11;
            this.filterButton.Text = "Filter";
            this.filterButton.UseVisualStyleBackColor = true;
            this.filterButton.Click += new System.EventHandler(this.filterButton_Click);
            // 
            // charTextBox
            // 
            this.charTextBox.Font = new System.Drawing.Font("Times New Roman", 9.75F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.charTextBox.Location = new System.Drawing.Point(695, 435);
            this.charTextBox.Margin = new System.Windows.Forms.Padding(4);
            this.charTextBox.Name = "charTextBox";
            this.charTextBox.OtherRichTextBox = null;
            this.charTextBox.ReadOnly = true;
            this.charTextBox.ScrollBars = System.Windows.Forms.RichTextBoxScrollBars.Vertical;
            this.charTextBox.Size = new System.Drawing.Size(409, 195);
            this.charTextBox.TabIndex = 9;
            this.charTextBox.Text = "";
            // 
            // hexTextBox
            // 
            this.hexTextBox.Font = new System.Drawing.Font("Times New Roman", 9.75F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.hexTextBox.Location = new System.Drawing.Point(4, 435);
            this.hexTextBox.Margin = new System.Windows.Forms.Padding(4);
            this.hexTextBox.Name = "hexTextBox";
            this.hexTextBox.OtherRichTextBox = null;
            this.hexTextBox.ReadOnly = true;
            this.hexTextBox.ScrollBars = System.Windows.Forms.RichTextBoxScrollBars.None;
            this.hexTextBox.Size = new System.Drawing.Size(693, 195);
            this.hexTextBox.TabIndex = 8;
            this.hexTextBox.Text = "";
            // 
            // columnHeader1
            // 
            this.columnHeader1.Text = "Source_IP";
            this.columnHeader1.Width = 120;
            // 
            // columnHeader2
            // 
            this.columnHeader2.Text = "Source_PORT";
            this.columnHeader2.TextAlign = System.Windows.Forms.HorizontalAlignment.Center;
            this.columnHeader2.Width = 120;
            // 
            // columnHeader3
            // 
            this.columnHeader3.Text = "Destination_IP";
            this.columnHeader3.TextAlign = System.Windows.Forms.HorizontalAlignment.Center;
            this.columnHeader3.Width = 120;
            // 
            // columnHeader4
            // 
            this.columnHeader4.Text = "Destination_PORT";
            this.columnHeader4.TextAlign = System.Windows.Forms.HorizontalAlignment.Center;
            this.columnHeader4.Width = 120;
            // 
            // columnHeader5
            // 
            this.columnHeader5.Text = "TYPE";
            this.columnHeader5.TextAlign = System.Windows.Forms.HorizontalAlignment.Center;
            // 
            // columnHeader6
            // 
            this.columnHeader6.Text = "TIME";
            this.columnHeader6.TextAlign = System.Windows.Forms.HorizontalAlignment.Center;
            // 
            // columnHeader7
            // 
            this.columnHeader7.Text = "TotalLength";
            this.columnHeader7.TextAlign = System.Windows.Forms.HorizontalAlignment.Center;
            this.columnHeader7.Width = 55;
            // 
            // columnHeader8
            // 
            this.columnHeader8.Text = "briedInfo";
            this.columnHeader8.TextAlign = System.Windows.Forms.HorizontalAlignment.Center;
            this.columnHeader8.Width = 58;
            // 
            // listView
            // 
            this.listView.Columns.AddRange(new System.Windows.Forms.ColumnHeader[] {
            this.columnHeader1,
            this.columnHeader2,
            this.columnHeader3,
            this.columnHeader4,
            this.columnHeader5,
            this.columnHeader6,
            this.columnHeader7,
            this.columnHeader8});
            this.listView.Font = new System.Drawing.Font("Times New Roman", 10.5F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.listView.FullRowSelect = true;
            this.listView.GridLines = true;
            this.listView.HideSelection = false;
            this.listView.Location = new System.Drawing.Point(5, 59);
            this.listView.Margin = new System.Windows.Forms.Padding(4);
            this.listView.Name = "listView";
            this.listView.Size = new System.Drawing.Size(1100, 376);
            this.listView.TabIndex = 6;
            this.listView.UseCompatibleStateImageBehavior = false;
            this.listView.View = System.Windows.Forms.View.Details;
            this.listView.SelectedIndexChanged += new System.EventHandler(this.listView_SelectedIndexChanged);
            // 
            // ipTextBox
            // 
            this.ipTextBox.Font = new System.Drawing.Font("Times New Roman", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.ipTextBox.ForeColor = System.Drawing.SystemColors.ScrollBar;
            this.ipTextBox.Location = new System.Drawing.Point(135, 15);
            this.ipTextBox.Margin = new System.Windows.Forms.Padding(4);
            this.ipTextBox.Name = "ipTextBox";
            this.ipTextBox.Size = new System.Drawing.Size(197, 30);
            this.ipTextBox.TabIndex = 3;
            this.ipTextBox.TextAlign = System.Windows.Forms.HorizontalAlignment.Right;
            this.toolTip1.SetToolTip(this.ipTextBox, "Filter Format(For source host only): IP, PORT, IP/PORT OR IP:PORT");
            this.ipTextBox.GotFocus += new System.EventHandler(this.ipTextBox_GotFocus);
            // 
            // filterCheckBox
            // 
            this.filterCheckBox.Font = new System.Drawing.Font("Times New Roman", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.filterCheckBox.Location = new System.Drawing.Point(37, 19);
            this.filterCheckBox.Margin = new System.Windows.Forms.Padding(4);
            this.filterCheckBox.Name = "filterCheckBox";
            this.filterCheckBox.Size = new System.Drawing.Size(137, 36);
            this.filterCheckBox.TabIndex = 0;
            this.filterCheckBox.Text = "filter";
            this.toolTip1.SetToolTip(this.filterCheckBox, "Filter via certain ip, port and protocol type before sniffing.");
            this.filterCheckBox.UseVisualStyleBackColor = true;
            this.filterCheckBox.CheckedChanged += new System.EventHandler(this.filterCheckBox_CheckedChanged);
            // 
            // MainForm
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(8F, 16F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(1112, 671);
            this.Controls.Add(this.filterButton);
            this.Controls.Add(this.allButton);
            this.Controls.Add(this.charTextBox);
            this.Controls.Add(this.hexTextBox);
            this.Controls.Add(this.typeComboBox);
            this.Controls.Add(this.listView);
            this.Controls.Add(this.clearButton);
            this.Controls.Add(this.hintLabel);
            this.Controls.Add(this.ipTextBox);
            this.Controls.Add(this.stopButton);
            this.Controls.Add(this.startButton);
            this.Controls.Add(this.filterCheckBox);
            this.FormBorderStyle = System.Windows.Forms.FormBorderStyle.FixedSingle;
            this.Icon = ((System.Drawing.Icon)(resources.GetObject("$this.Icon")));
            this.Margin = new System.Windows.Forms.Padding(4);
            this.MaximizeBox = false;
            this.Name = "MainForm";
            this.StartPosition = System.Windows.Forms.FormStartPosition.CenterScreen;
            this.Text = "Hearen\'s SimpleSniffer";
            this.TopMost = true;
            this.FormClosing += new System.Windows.Forms.FormClosingEventHandler(this.MainFrom_FormClosing);
            this.Load += new System.EventHandler(this.MainForm_Load);
            ((System.ComponentModel.ISupportInitialize)(this.packetBindingSource)).EndInit();
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        

        #endregion
        private System.Windows.Forms.Button startButton;
        private System.Windows.Forms.Button stopButton;
        private System.Windows.Forms.ToolTip toolTip1;
        private System.Windows.Forms.Label hintLabel;
        private MyButton clearButton;
        private System.Windows.Forms.BindingSource packetBindingSource;
        private ColumnHeader header;
        private ComboBox typeComboBox;
        private MyRichTextBox hexTextBox;
        private MyRichTextBox charTextBox;
        private Button allButton;
        private Button filterButton;
        private ToolTip toolTip2;
        private ToolTip toolTip3;
        private ColumnHeader columnHeader1;
        private ColumnHeader columnHeader2;
        private ColumnHeader columnHeader3;
        private ColumnHeader columnHeader4;
        private ColumnHeader columnHeader5;
        private ColumnHeader columnHeader6;
        private ColumnHeader columnHeader7;
        private ColumnHeader columnHeader8;
        private ListView listView;
        private TextBox ipTextBox;
        private CheckBox filterCheckBox;
    }
}