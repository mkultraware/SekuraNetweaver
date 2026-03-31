using System;
using System.Drawing;
using System.Windows.Forms;
using System.Runtime.InteropServices;

namespace SekuraNetweaver.UI;

public class ActionNotification : Form
{
    public event EventHandler? OnTrusted;

    private readonly string _processName;
    private readonly string _ip;
    private readonly string _domain;
    private readonly int _level;

    [DllImport("user32.dll")]
    private static extern bool ReleaseCapture();
    [DllImport("user32.dll")]
    private static extern int SendMessage(IntPtr hWnd, int Msg, int wParam, int lParam);

    public ActionNotification(string processName, string ip, string domain, int level)
    {
        _processName = processName;
        _ip = ip;
        _domain = domain;
        _level = level;

        InitializeComponent();
        
        // Position at bottom right
        var screen = Screen.PrimaryScreen?.WorkingArea ?? Screen.FromControl(this).WorkingArea;
        this.Location = new Point(screen.Right - this.Width - 10, screen.Bottom - this.Height - 10);
        this.TopMost = true;
    }

    private void InitializeComponent()
    {
        this.Size = new Size(350, 180);
        this.FormBorderStyle = FormBorderStyle.None;
        this.BackColor = Color.FromArgb(20, 20, 25);
        this.ShowInTaskbar = false;

        Label title = new Label
        {
            Text = "⚠️ Suspicious Network Activity",
            ForeColor = Color.FromArgb(255, 80, 80),
            Font = new Font("Segoe UI", 12, FontStyle.Bold),
            Location = new Point(15, 15),
            AutoSize = true
        };

        Label info = new Label
        {
            Text = $"Process: {_processName}\nTarget: {_ip}\nDomain: {_domain}\nAlert Level: {(AlertLevel)_level}",
            ForeColor = Color.White,
            Font = new Font("Segoe UI", 10),
            Location = new Point(15, 45),
            Size = new Size(320, 80)
        };

        Button trustBtn = new Button
        {
            Text = "Trust This",
            Size = new Size(100, 35),
            Location = new Point(15, 130),
            FlatStyle = FlatStyle.Flat,
            BackColor = Color.FromArgb(40, 180, 120),
            ForeColor = Color.White,
            Font = new Font("Segoe UI", 9, FontStyle.Bold)
        };
        trustBtn.FlatAppearance.BorderSize = 0;
        trustBtn.Click += (s, e) => { OnTrusted?.Invoke(this, EventArgs.Empty); this.Close(); };

        Button blockBtn = new Button
        {
            Text = "Dismiss",
            Size = new Size(100, 35),
            Location = new Point(125, 130),
            FlatStyle = FlatStyle.Flat,
            BackColor = Color.FromArgb(60, 60, 70),
            ForeColor = Color.White,
            Font = new Font("Segoe UI", 9)
        };
        blockBtn.FlatAppearance.BorderSize = 0;
        blockBtn.Click += (s, e) => this.Close();

        this.Controls.AddRange(new Control[] { title, info, trustBtn, blockBtn });

        // Add rounded corners and border
        this.Paint += (s, e) =>
        {
            e.Graphics.DrawRectangle(new Pen(Color.FromArgb(50, 50, 60), 1), 0, 0, this.Width - 1, this.Height - 1);
        };

        this.MouseDown += (s, e) =>
        {
            if (e.Button == MouseButtons.Left)
            {
                ReleaseCapture();
                SendMessage(Handle, 0xA1, 0x2, 0);
            }
        };
    }

    private enum AlertLevel
    {
        Info = 0,
        Low = 1,
        Medium = 2,
        High = 3,
        Critical = 4
    }
}
