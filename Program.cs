using System; 
using System.Threading;
using System.Windows.Forms;

namespace SekuraNetweaver;

static class Program
{
    private static Mutex _mutex = null!;

    [STAThread]
    static void Main()
    {
        const string appGuid = "c0a8f8d0-1234-4567-89ab-cdef01234567";
        bool createdNew;

        _mutex = new Mutex(true, appGuid, out createdNew);

        if (!createdNew)
        {
            // Already running
            return;
        }

        // Check if running as administrator
        using (var identity = System.Security.Principal.WindowsIdentity.GetCurrent())
        {
            var principal = new System.Security.Principal.WindowsPrincipal(identity);
            if (!principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator))
            {
                MessageBox.Show("SekuraNetweaver requires Administrator privileges to monitor processes via PowerShell.", "Permission Denied", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }

        ApplicationConfiguration.Initialize();
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);
        Application.Run(new TrayApp());

    }
}

