using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;

namespace RestHeadersGenerator
{
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
        }

        private void btnGenerateHeaders_Click(object sender, RoutedEventArgs e)
        {
            string actualDate = DateTime.UtcNow.ToString("R");

            //generar Header de Autorización
            string storageAccount = txtStorageAccount.Text;
            string storageKey = txtStorageKey.Text;
            txtAuthorization.Text = GenerateAuthorizationHeader(actualDate, storageAccount, storageKey);

            //generar Header de fecha
            txtDate.Text = actualDate;

            //generar Header de version
            txtVersion.Text = "2014-02-14";
        }

        string GenerateAuthorizationHeader(string mxdate, string storageName, string sharedAccessKey)
        {
            mxdate = DateTime.UtcNow.ToString("R");

            string canonicalizedHeaders = string.Format(
                "x-ms-date:{0}\nx-ms-version:{1}",
                mxdate,
                "2014-02-14");

            string canonicalizedResource = string.Format("/{0}/\ncomp:list", storageName);

            string stringToSign = string.Format(
            "{0}\n\n\n\n\n\n\n\n\n\n\n\n{1}\n{2}",
            "GET",
            canonicalizedHeaders,
            canonicalizedResource);

            HMACSHA256 hmac = new HMACSHA256(Convert.FromBase64String(sharedAccessKey));

            string signature = Convert.ToBase64String(hmac.ComputeHash(Encoding.UTF8.GetBytes(stringToSign)));

            String authorization = String.Format("{0} {1}:{2}",
            "SharedKey",
            storageName,
            signature
            );

            return authorization;
        }
    }
}
