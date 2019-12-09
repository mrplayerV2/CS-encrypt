using System;
using System.Security.Cryptography;
using System.Text;

public class Encrypt
{
	public static string GetMD5(string p)
	{
		try
		{
			return BitConverter.ToString(new MD5CryptoServiceProvider().ComputeHash(Encoding.UTF8.GetBytes(p))).Replace("-", string.Empty);
		}
		catch (Exception)
		{
			return "";
		}
	}

	public static string EncryptAES(string strEnc, string key)
	{
		try
		{
			byte[] bytes = Encoding.UTF8.GetBytes(strEnc);
			RijndaelManaged rijndaelManaged = new RijndaelManaged();
			MD5CryptoServiceProvider mD5CryptoServiceProvider = new MD5CryptoServiceProvider();
			rijndaelManaged.Key = mD5CryptoServiceProvider.ComputeHash(Encoding.UTF8.GetBytes(key));
			rijndaelManaged.Mode = CipherMode.ECB;
			rijndaelManaged.Padding = PaddingMode.PKCS7;
			byte[] array = rijndaelManaged.CreateEncryptor().TransformFinalBlock(bytes, 0, bytes.Length);
			return Convert.ToBase64String(array, 0, array.Length);
		}
		catch (Exception)
		{
			return "";
		}
	}

	public static string DecryptAES(string strDec, string key)
	{
		try
		{
			byte[] array = Convert.FromBase64String(strDec);
			RijndaelManaged rijndaelManaged = new RijndaelManaged();
			MD5CryptoServiceProvider mD5CryptoServiceProvider = new MD5CryptoServiceProvider();
			rijndaelManaged.Key = mD5CryptoServiceProvider.ComputeHash(Encoding.UTF8.GetBytes(key));
			rijndaelManaged.Mode = CipherMode.ECB;
			rijndaelManaged.Padding = PaddingMode.PKCS7;
			byte[] bytes = rijndaelManaged.CreateDecryptor().TransformFinalBlock(array, 0, array.Length);
			return Encoding.UTF8.GetString(bytes);
		}
		catch (Exception)
		{
			return "";
		}
	}
}