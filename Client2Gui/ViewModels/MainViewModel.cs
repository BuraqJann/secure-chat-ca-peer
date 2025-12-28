using System;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Net;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Shared;

namespace Client2Gui.ViewModels;

public sealed class MainViewModel : INotifyPropertyChanged
{
    private const string MyId = "Client2";
    private const string ExpectedPeerId = "Client1";

    public event PropertyChangedEventHandler? PropertyChanged;

    private string _caIp = "10.0.0.10";
    private int _caPort = 5000;

    private string _listenIp = "10.0.0.12";
    private int _listenPort = 6000;

    private string _peerIp = "10.0.0.11"; // Client1 IP
    private int _peerPort = 6000;

    private string _messageText = "";
    private string _status = "Idle";

    private TcpListener? _listener;
    private TcpClient? _client;
    private NetworkStream? _stream;
    private CancellationTokenSource? _cts;
    private byte[]? _ks;

    private readonly RSA _myRsa = RSA.Create(2048);

    public ObservableCollection<ChatMessage> Messages { get; } = new();

    public string CaIp { get => _caIp; set { _caIp = value; OnChanged(); RefreshCommands(); } }
    public int CaPort { get => _caPort; set { _caPort = value; OnChanged(); RefreshCommands(); } }

    public string ListenIp { get => _listenIp; set { _listenIp = value; OnChanged(); RefreshCommands(); } }
    public int ListenPort { get => _listenPort; set { _listenPort = value; OnChanged(); RefreshCommands(); } }

    public string PeerIp { get => _peerIp; set { _peerIp = value; OnChanged(); RefreshCommands(); } }
    public int PeerPort { get => _peerPort; set { _peerPort = value; OnChanged(); RefreshCommands(); } }

    public string MessageText { get => _messageText; set { _messageText = value; OnChanged(); RefreshCommands(); } }

    public string Status { get => _status; private set { _status = value; OnChanged(); } }

    public bool IsConnected => _stream != null && _ks != null;

    public AsyncCommand ListenCommand { get; }
    public AsyncCommand ConnectCommand { get; }
    public AsyncCommand DisconnectCommand { get; }
    public AsyncCommand SendCommand { get; }

    public MainViewModel()
    {
        ListenCommand = new AsyncCommand(ListenAsync, () => !IsConnected);
        ConnectCommand = new AsyncCommand(ConnectAsync, () => !IsConnected);
        DisconnectCommand = new AsyncCommand(DisconnectAsync, () => IsConnected || _listener != null);
        SendCommand = new AsyncCommand(SendAsync, () => IsConnected && !string.IsNullOrWhiteSpace(MessageText));
    }

    private void RefreshCommands()
    {
        ListenCommand.RaiseCanExecuteChanged();
        ConnectCommand.RaiseCanExecuteChanged();
        DisconnectCommand.RaiseCanExecuteChanged();
        SendCommand.RaiseCanExecuteChanged();
        OnChanged(nameof(IsConnected));
    }

    private async Task ListenAsync()
    {
        await DisconnectAsync();

        _cts = new CancellationTokenSource();
        var ct = _cts.Token;

        try
        {
            Status = $"Listening {ListenIp}:{ListenPort} ...";
            _listener = new TcpListener(IPAddress.Parse(ListenIp), ListenPort);
            _listener.Start();

            _client = await _listener.AcceptTcpClientAsync(ct);
            _stream = _client.GetStream();

            Status = "Handshake (Responder) ...";

            var (ks, myCert, peerCert) = await PeerHandshake.StartAsResponderAsync(
                _stream, CaIp, CaPort, _myRsa, MyId, ExpectedPeerId, ct);

            _ks = ks;

            Messages.Add(new ChatMessage(true, "System", $"✅ Secure channel ready. Peer={peerCert.SubjectId}"));
            Status = "Connected ✅";
            RefreshCommands();

            _ = Task.Run(() => ReceiveLoopAsync(ct));
        }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        {
            Messages.Add(new ChatMessage(true, "Error", ex.Message));
            Status = "Error";
            await DisconnectAsync();
        }
    }

    private async Task ConnectAsync()
    {
        await DisconnectAsync();

        _cts = new CancellationTokenSource();
        var ct = _cts.Token;

        try
        {
            Status = $"Connecting to {PeerIp}:{PeerPort} ...";

            _client = new TcpClient();
            await _client.ConnectAsync(PeerIp, PeerPort, ct);
            _stream = _client.GetStream();

            Status = "Handshake (Initiator) ...";

            var (ks, myCert, peerCert) = await PeerHandshake.StartAsInitiatorAsync(
                _stream, CaIp, CaPort, _myRsa, MyId, ExpectedPeerId, ct);

            _ks = ks;

            Messages.Add(new ChatMessage(true, "System", $"✅ Secure channel ready. Peer={peerCert.SubjectId}"));
            Status = "Connected ✅";
            RefreshCommands();

            _ = Task.Run(() => ReceiveLoopAsync(ct));
        }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        {
            Messages.Add(new ChatMessage(true, "Error", ex.Message));
            Status = "Error";
            await DisconnectAsync();
        }
    }

    private async Task ReceiveLoopAsync(CancellationToken ct)
    {
        if (_stream == null || _ks == null) return;

        string aadIn = $"from={ExpectedPeerId};to={MyId};v=1";

        try
        {
            while (!ct.IsCancellationRequested)
            {
                string incoming = await Framing.ReadStringAsync(_stream, ct);

                if (incoming == "BYE")
                {
                    Messages.Add(new ChatMessage(true, "System", "Peer closed the chat."));
                    await DisconnectAsync();
                    return;
                }

                if (incoming.StartsWith("MSG|"))
                {
                    string b64 = incoming.Substring(4);
                    try
                    {
                        string plain = Crypto.AesGcmDecryptFromBase64(_ks, b64, aadIn);
                        Messages.Add(new ChatMessage(false, ExpectedPeerId, plain));
                    }
                    catch (CryptographicException)
                    {
                        Messages.Add(new ChatMessage(true, "System", "⚠️ Decrypt failed (tamper/wrong AAD)."));
                    }
                }
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        {
            Messages.Add(new ChatMessage(true, "Error", "ReceiveLoop: " + ex.Message));
            await DisconnectAsync();
        }
    }

    private async Task SendAsync()
    {
        if (_stream == null || _ks == null) return;

        string text = MessageText.TrimEnd();
        if (string.IsNullOrWhiteSpace(text)) return;

        string aadOut = $"from={MyId};to={ExpectedPeerId};v=1";
        string packed = Crypto.AesGcmEncryptToBase64(_ks, text, aadOut);

        await Framing.SendStringAsync(_stream, "MSG|" + packed);
        Messages.Add(new ChatMessage(true, MyId, text));

        MessageText = "";
        RefreshCommands();
    }

    private Task DisconnectAsync()
    {
        try { _cts?.Cancel(); } catch { }

        try { _stream?.Close(); } catch { }
        try { _client?.Close(); } catch { }
        try { _listener?.Stop(); } catch { }

        _stream = null;
        _client = null;
        _listener = null;
        _cts = null;
        _ks = null;

        Status = "Idle";
        RefreshCommands();

        return Task.CompletedTask;
    }

    private void OnChanged([CallerMemberName] string? name = null)
        => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}

public sealed class ChatMessage
{
    public ChatMessage(bool isMe, string sender, string text)
    {
        IsMe = isMe;
        Sender = sender;
        Text = text;
        Time = DateTime.Now.ToString("HH:mm");
    }

    public bool IsMe { get; }
    public string Sender { get; }
    public string Text { get; }
    public string Time { get; }
}
