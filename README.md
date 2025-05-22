# METIS - Monitoring Endpoint Traffic Intelligence System

\METIS は、家庭ネットワークや教育環境におけるネットワーク通信の3D可視化ツールです。
Unityによってネットワークノードと通信の流れを可視化し、Python（Scapy）でリアルタイムにパケットを監視・解析します。 開発者への連絡やご意見があれば、お気軽に以下のフォームまたはメールでお知らせください。 vanson.norton0506@icluod.com https://github.com/bastyn0506/METIS.linux/blob/main/README%20en.md [English README]

⚠️ 注意・免責 このツールは教育・研究用途向けです。実運用環境での使用は自己責任でお願いします。 セキュリティ意識の啓発やトラフィック理解を目的としています。

---

## 🔰 主な特徴

### 🐍 Python（packet_sniffer.py）
- Scapyによるリアルタイムパケットキャプチャ
- 危険ポート（例：23番など）への通信を自動検出
- 一定時間内に多ポートアクセスされた場合の簡易ポートスキャン検知
- SSL/TLS通信からの **SNI抽出** および **TLSバージョン解析**
- **IoC検出**CIRCLからIP/ドメイン/URLを取得して照合）
- **Tor出口ノードの検出**（GitHub上の最新リストを参照）
- リアルタイム設定反映（`config.json` を監視）
- WebSocketを用いたUnityへのリアルタイムデータ送信
- JSON Lines形式での通信ログ保存

### 🎮 Unity（可視化）
- 通信元・宛先IPをノードとして3D空間に可視化
- 通信の流れをパケットのようなエフェクトで表示
- 危険通信に応じてノードを色で強調表示
- 各ノードの下に脅威スコアを表示（TextMeshPro）
- 設定画面から、危険ポートや信頼IP、音量などを変更可能（`config.json` へ保存）

---

## 🧩 構成

- Python側：サーバーとしてパケットをキャプチャ・解析・送信
- Unity側：別端末や同一LAN上でリアルタイムに通信可視化
- 複数端末（VPSとローカルPC）間での連携も確認済み

---

## 🚀 今後の予定機能
- MISPとのIoC自動連携
- ファイルハッシュ（SHA256など）による検出
- SSL証明書情報の可視化
- より高度なスコアリングエンジン
- セキュリティ教育コンテンツとしてのパッケージ化

---

##  動作の仕組み


-ユーザー操作         
-config.json の設定変更     
-信頼IP・危険ポートの指定
            
            
-🐍 Python - packet_sniffer.py 
-Scapyでパケットキャプチャ     
-危険ポート検出／スキャン検知   
-SNI/TLSバージョン抽出        
-IoC（IP/ドメイン）照合       
-Tor出口ノード判定            
-GeoIPで国情報取得            
-脅威スコアを計算             
-WebSocketでUnityに送信       
             

-🎮 Unity - METIS 3D可視化システム
-IPノードと通信の3D表示        
-危険通信は赤色で警告表示      
-脅威スコアを数値と色で可視化   
-統計UI（ポート/IP/国別）      
-設定UIから閾値等を変更        

             

-👨‍💻 ユーザー操作・教育用途      
-通信可視化、スキャンログの確認   
-セキュリティ教育や技術デモ用途  

---

## 📽️ デモ動画はこちら！

https://youtu.be/-eKr9tY0Bhc

---


## 🛠 使用技術

- Python 3.10+
- Scapy
- Unity 2022+
- TextMeshPro, WebSocket, Thread, LineRenderer など

---

## 📦 ライセンス

MIT License  
© 2025 bastyn0506

---

## 💬 補足

このツールは教育・研究用途を主目的としています。  
商用ネットワークでの利用には十分な検証を行ってください。
