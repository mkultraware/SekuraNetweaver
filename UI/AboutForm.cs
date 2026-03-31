using System;
using System.Drawing;
using System.Windows.Forms;

namespace SekuraNetweaver.UI;

public class AboutForm : Form
{
    public AboutForm()
    {
        InitializeComponent();
    }

    private void InitializeComponent()
    {
        this.Text = "About SekuraNetweaver";
        this.Size = new Size(400, 300);
        this.FormBorderStyle = FormBorderStyle.FixedDialog;
        this.MaximizeBox = false;
        this.MinimizeBox = false;
        this.StartPosition = FormStartPosition.CenterScreen;
        this.BackColor = Color.FromArgb(30, 30, 30);
        this.ForeColor = Color.White;

        var titleLabel = new Label
        {
            Text = "SekuraNetweaver v1.3.0",
            Font = new Font("Segoe UI", 16, FontStyle.Bold),
            Location = new Point(20, 20),
            AutoSize = true,
            ForeColor = Color.FromArgb(0, 120, 215)
        };

        var descLabel = new Label
        {
            Text = "Advanced Network & Process Monitor\n\nIdentifying suspicious connections and unauthorized process activities to help you keep your system secure.\r\n\r\nFeatures:\n- Real-time Connection Monitoring\n- Process Path Identification\n- DNS Switching Engine\n- One-click Whitelisting",
            Font = new Font("Segoe UI", 10),
            Location = new Point(20, 60),
            Size = new Size(360, 140),
            ForeColor = Color.FromArgb(200, 200, 200)
        };

        var copyrightLabel = new Label
        {
            Text = "© 2026 SekuraNetweaver. All rights reserved.",
            Font = new Font("Segoe UI", 8),
            Location = new Point(20, 210),
            AutoSize = true,
            ForeColor = Color.Gray
        };

        var closeButton = new Button
        {
            Text = "Close",
            Location = new Point(290, 220),
            Size = new Size(80, 30),
            FlatStyle = FlatStyle.Flat,
            BackColor = Color.FromArgb(60, 60, 60),
            Cursor = Cursors.Hand
        };
        closeButton.Click += (s, e) => this.Close();

        var socialLink = new LinkLabel
        {
            Text = "Follow us on Twitter",
            Font = new Font("Segoe UI", 10),
            Location = new Point(20, 240),
            AutoSize = true,
            LinkColor = Color.FromArgb(29, 161, 242)
        };
        socialLink.LinkClicked += (s, e) => {
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("https://x.com/NoJetsNextDoor") { UseShellExecute = true });
        };

        this.Controls.Add(titleLabel);
        this.Controls.Add(descLabel);
        this.Controls.Add(copyrightLabel);
        this.Controls.Add(socialLink);
        this.Controls.Add(closeButton);
    }
}
