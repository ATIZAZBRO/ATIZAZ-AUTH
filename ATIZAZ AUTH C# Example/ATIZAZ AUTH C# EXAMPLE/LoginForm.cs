using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

using AtizazAuth;

namespace ATIZAZ_AUTH_CSharp_EXAMPLE
{
    public partial class LoginForm : Form
    {
     
        public static AtizazAuthAPI api = new AtizazAuthAPI(
            apiUrl: "https://cmatizaz-cfire.atizazfayaz78.workers.dev",
            secretKey: "ENTER SCRET", 
            applicationName: "ENTER NAME",
            version: "1.0"
        );

        public LoginForm()
        {
            InitializeComponent();
            api.Init();
        }

        private void LoginForm_Load(object sender, EventArgs e)
        {
            api.Init();
        }

        private async void loginbtn_Click(object sender, EventArgs e)
        {
            if (string.IsNullOrWhiteSpace(username.Text) || string.IsNullOrWhiteSpace(password.Text))
            {
                MessageBox.Show("Please enter username and password!");
                return;
            }
            var response = await api.Login(username.Text, password.Text);

            if (response.success)
            {
                MessageBox.Show("LOGIN SUCCESS!");
                this.Hide();
                MainForm mainForm = new MainForm();
                mainForm.Show();
            }
            else
            {
                MessageBox.Show($"Login Failed: {response.message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }

        }

        private async void LicenseLoginbtn_Click(object sender, EventArgs e)
        {
            if (string.IsNullOrWhiteSpace(LicenseKey.Text))
            {
                MessageBox.Show("Please enter a license key!");
                return;
            }

            var response = await api.License(LicenseKey.Text);

            if (response != null && response.success)
            {
                MessageBox.Show("LOGIN SUCCESS!");
                this.Hide();
                MainForm mainForm = new MainForm();
                mainForm.Show();
            }
            else
            {
                MessageBox.Show($"Login Failed: {(response != null ? response.message : "Unknown Error")}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }
    }
}
