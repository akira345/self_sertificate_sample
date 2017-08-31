using Org.BouncyCastle.Crypto;
using System.IO;
using System.Security.Cryptography;
using System.Windows.Forms;
using System.Security.Cryptography.X509Certificates;
using System;
using Org.BouncyCastle.OpenSsl;

namespace self_sertificate_sample
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
        }

        private void button1_Click(object sender, System.EventArgs e)
        {
            //サンプルなので保存先は適当
            Generate_Self_Certificate("c:\\temp", "c:\\temp", "example.com");
            MessageBox.Show("OK");
        }
        /// <summary>
        /// オレオレ証明書を作成します。
        /// </summary>
        /// <param name="cert_path">作成したCA公開鍵及び証明書ファイルの保存先</param>
        /// <param name="key_path">作成した証明書秘密鍵保存先</param>
        /// <param name="hostname">作成する証明書のホスト名</param>
        public static void Generate_Self_Certificate(string cert_path, string key_path, string hostname)
        {
            AsymmetricKeyParameter myCAprivateKey = null;

            string ca_certificate_info = "C=JP, ST=Hiroshima, L=Hiroshima, O=, OU=, CN=CA";//認証局情報
            string server_certificate_info = "C=JP, ST=Hiroshima, L=Hiroshima, O=, OU=, OU=CA, CN=" + hostname; //サーバ証明書情報

            //認証局作成
            Console.WriteLine("Creating CA");

            X509Certificate2 certificateAuthorityCertificate = Cert_Utils.CreateCertificateAuthorityCertificate(ca_certificate_info, ref myCAprivateKey);

            MessageBox.Show(certificateAuthorityCertificate.ToString(true));
            MessageBox.Show(certificateAuthorityCertificate.ToString(false));

            //CA公開鍵保存(PEM)
            File.WriteAllText(cert_path + "\\" + hostname + ".ca", Cert_Utils.GetPublickeyPemString(certificateAuthorityCertificate));

            //CA秘密鍵保存(PEM)を保存する場合
            var ca_key_parameter = certificateAuthorityCertificate.GetRSAPrivateKey().ExportParameters(true);
            var ca_privateKey = RsaPemMaker.GetPrivatePemString(ca_key_parameter);
            File.WriteAllText(key_path + "\\" + hostname + ".cakey", ca_privateKey);

            //作成したCAの秘密鍵を読み込む
            myCAprivateKey = readPrivateKey(key_path + "\\" + hostname + ".cakey");

            //サーバ証明書を作成し、CAの秘密鍵で署名する。
            Console.WriteLine("Creating certificate based on CA");
            X509Certificate2 certificate = Cert_Utils.CreateSelfSignedCertificateBasedOnCertificateAuthorityPrivateKey(server_certificate_info, ca_certificate_info, myCAprivateKey);

            //サーバ証明書公開鍵保存(PEM)
            File.WriteAllText(cert_path + "\\" + hostname + ".crt", Cert_Utils.GetPublickeyPemString(certificate));

            //サーバ証明書秘密鍵保存(PEM)
            RSAParameters key_parameter = certificate.GetRSAPrivateKey().ExportParameters(true);
            string privateKey = RsaPemMaker.GetPrivatePemString(key_parameter);
            File.WriteAllText(key_path + "\\" + hostname + ".key", privateKey);
            Console.WriteLine(privateKey);
        }
        /// <summary>
        /// プライベートキーを読み込みます。
        /// </summary>
        /// <param name = "privateKeyFileName" > PEM形式のプライベートキーファイル名 </ param >
        /// < returns ></ returns >
        private static AsymmetricKeyParameter readPrivateKey(string privateKeyFileName)
        {
            AsymmetricCipherKeyPair keyPair;

            using (var reader = File.OpenText(privateKeyFileName))
            {
                keyPair = (AsymmetricCipherKeyPair)new PemReader(reader).ReadObject();
            }
            return keyPair.Private;
        }

    }
}
