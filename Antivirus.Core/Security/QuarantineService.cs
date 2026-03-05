using System.Security.Cryptography;
using Microsoft.Data.Sqlite;

namespace Antivirus.Core.Security;

public sealed class QuarantineService
{
	private readonly string _dbPath;
	private readonly string _quarantineDir;
	//путь к пустой бд
	public QuarantineService()
	{
		var appData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
		var root = Path.Combine(appData, "AntivirusApp");
		Directory.CreateDirectory(root);

		_dbPath = Path.Combine(root, "antivirus.db");
		_quarantineDir = Path.Combine(root, "Quarantine");
		Directory.CreateDirectory(_quarantineDir);

		EnsureDatabase();
	}
	//конект
	private SqliteConnection Open()
	{
		var conn = new SqliteConnection($"Data Source={_dbPath}");
		conn.Open();
		return conn;
	}
	//заполняем пустую бдшку
	private void EnsureDatabase()
	{
		using var conn = Open();
		using var cmd = conn.CreateCommand();
		cmd.CommandText = @"
CREATE TABLE IF NOT EXISTS QuarantineItem (
	Id                INTEGER PRIMARY KEY AUTOINCREMENT,
	OriginalPath      TEXT    NOT NULL,
	QuarantinePath    TEXT    NOT NULL,
	Sha256            TEXT,
	SizeBytes         INTEGER NOT NULL,
	QuarantinedUtc    TEXT    NOT NULL,
	Action            TEXT    NOT NULL,
	RestoredUtc       TEXT,
	DeletedUtc        TEXT,
	Notes             TEXT
);
CREATE INDEX IF NOT EXISTS IX_QuarantineItem_QuarantinedUtc ON QuarantineItem(QuarantinedUtc);
CREATE INDEX IF NOT EXISTS IX_QuarantineItem_DeletedUtc ON QuarantineItem(DeletedUtc);";
		cmd.ExecuteNonQuery();
	}
	//хэши
	private static string ComputeSha256(string filePath)
	{
		using var stream = File.OpenRead(filePath);
		using var sha = SHA256.Create();
		var hash = sha.ComputeHash(stream);
		return Convert.ToHexString(hash);
	}

	private static string MakeSafeFileName(string originalPath)
	{
		var name = Path.GetFileName(originalPath);
		foreach (var ch in Path.GetInvalidFileNameChars())
			name = name.Replace(ch, '_');
		return name;
	}
	//в карантин
	public int MoveToQuarantine(string originalPath, string? note = null)
	{
		if (!File.Exists(originalPath))
			throw new FileNotFoundException("Файл не найден", originalPath);

		var info = new FileInfo(originalPath);
		var sha256 = ComputeSha256(originalPath);
		var unique = $"{DateTime.UtcNow:yyyyMMddHHmmssfff}_{Guid.NewGuid():N}_{MakeSafeFileName(originalPath)}";
		var quarantinePath = Path.Combine(_quarantineDir, unique);

		using var conn = Open();
		using var tx = conn.BeginTransaction();

		int id;
		try
		{
			// 1) Пишем запись в БД в транзакции
			using (var cmd = conn.CreateCommand())
			{
				cmd.CommandText = @"INSERT INTO QuarantineItem
(OriginalPath, QuarantinePath, Sha256, SizeBytes, QuarantinedUtc, Action, Notes)
VALUES ($orig, $q, $sha, $size, $ts, 'Move', $notes);
SELECT last_insert_rowid();";
				cmd.Parameters.AddWithValue("$orig", originalPath);
				cmd.Parameters.AddWithValue("$q", quarantinePath);
				cmd.Parameters.AddWithValue("$sha", sha256);
				cmd.Parameters.AddWithValue("$size", info.Length);
				cmd.Parameters.AddWithValue("$ts", DateTime.UtcNow.ToString("o"));
				cmd.Parameters.AddWithValue("$notes", (object?)note ?? DBNull.Value);
				id = Convert.ToInt32(cmd.ExecuteScalar());
			}

			// 2) Перемещаем файл. 
			File.Move(originalPath, quarantinePath, overwrite: false);

			// 3) Фиксируем прибыль
			tx.Commit();
		}
		catch
		{
			try
			{
				// выкупаем если всё поломалось
				if (File.Exists(quarantinePath) && !File.Exists(originalPath))
				{
					Directory.CreateDirectory(Path.GetDirectoryName(originalPath)!);
					File.Move(quarantinePath, originalPath);
				}
			}
			catch { /* ожидаем  */ }

			// ставка выкуплена
			try { tx.Rollback(); } catch { }
			throw;
		}

		return id;
	}
	//из карантина
	public void Restore(int id)
	{
		using var conn = Open();

		string? orig = null, qpath = null;
		using (var read = conn.CreateCommand())
		{
			read.CommandText = "SELECT OriginalPath, QuarantinePath, DeletedUtc, RestoredUtc FROM QuarantineItem WHERE Id=$id";
			read.Parameters.AddWithValue("$id", id);
			using var r = read.ExecuteReader();
			if (!r.Read())
				throw new InvalidOperationException("Элемент карантина не найден");

			if (!r.IsDBNull(2)) throw new InvalidOperationException("Файл уже удалён");
			if (!r.IsDBNull(3)) throw new InvalidOperationException("Файл уже восстановлен");

			orig = r.GetString(0);
			qpath = r.GetString(1);
		}

		if (!File.Exists(qpath!))
			throw new FileNotFoundException("Файл отсутствует в карантине", qpath);
		//данные чек
		Directory.CreateDirectory(Path.GetDirectoryName(orig!)!);

		var dest = orig!;
		if (File.Exists(dest))
		{
			var dir = Path.GetDirectoryName(dest)!;
			var name = Path.GetFileNameWithoutExtension(dest);
			var ext = Path.GetExtension(dest);
			dest = Path.Combine(dir, $"{name}_restored_{DateTime.Now:yyyyMMddHHmmss}{ext}");
		}

		File.Move(qpath!, dest, overwrite: false);

		using (var upd = conn.CreateCommand())
		{
			upd.CommandText = "UPDATE QuarantineItem SET RestoredUtc=$ts WHERE Id=$id";
			upd.Parameters.AddWithValue("$ts", DateTime.UtcNow.ToString("o"));
			upd.Parameters.AddWithValue("$id", id);
			upd.ExecuteNonQuery();
		}
	}
	//удалить
	public void DeletePermanently(int id)
	{
		using var conn = Open();

		string? qpath = null;
		using (var read = conn.CreateCommand())
		{
			read.CommandText = "SELECT QuarantinePath, DeletedUtc FROM QuarantineItem WHERE Id=$id";
			read.Parameters.AddWithValue("$id", id);
			using var r = read.ExecuteReader();
			if (!r.Read())
				throw new InvalidOperationException("Элемент карантина не найден");
			if (!r.IsDBNull(1)) return;
			qpath = r.GetString(0);
		}

		if (File.Exists(qpath!))
			File.Delete(qpath!);

		using (var upd = conn.CreateCommand())
		{
			upd.CommandText = "UPDATE QuarantineItem SET DeletedUtc=$ts WHERE Id=$id";
			upd.Parameters.AddWithValue("$ts", DateTime.UtcNow.ToString("o"));
			upd.Parameters.AddWithValue("$id", id);
			upd.ExecuteNonQuery();
		}
	}

	public sealed record QuarantineRow(int Id, string OriginalPath, string QuarantinePath, string? Sha256, long SizeBytes, DateTime QuarantinedUtc, string Action, DateTime? RestoredUtc, DateTime? DeletedUtc, string? Notes);

	public IEnumerable<QuarantineRow> List(bool includeDeleted = false)
	{
		using var conn = Open();
		using var cmd = conn.CreateCommand();
		cmd.CommandText = includeDeleted
			? "SELECT Id, OriginalPath, QuarantinePath, Sha256, SizeBytes, QuarantinedUtc, Action, RestoredUtc, DeletedUtc, Notes FROM QuarantineItem ORDER BY QuarantinedUtc DESC"
			: "SELECT Id, OriginalPath, QuarantinePath, Sha256, SizeBytes, QuarantinedUtc, Action, RestoredUtc, DeletedUtc, Notes FROM QuarantineItem WHERE DeletedUtc IS NULL ORDER BY QuarantinedUtc DESC";
		using var r = cmd.ExecuteReader();
		while (r.Read())
		{
			yield return new QuarantineRow(
				r.GetInt32(0),
				r.GetString(1),
				r.GetString(2),
				r.IsDBNull(3) ? null : r.GetString(3),
				r.GetInt64(4),
				DateTime.Parse(r.GetString(5)),
				r.GetString(6),
				r.IsDBNull(7) ? null : DateTime.Parse(r.GetString(7)),
				r.IsDBNull(8) ? null : DateTime.Parse(r.GetString(8)),
				r.IsDBNull(9) ? null : r.GetString(9)
			);
		}
	}
}


