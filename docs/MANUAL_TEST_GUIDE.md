# AgentSafe 支付流程手工測試指南(PROMPT 4)

適用部署:`https://x402.workfern.com/`(或本地 `uvicorn agentsafe.server:...`)。
前置:MetaMask(或任一 EIP-1193 錢包)、Base Sepolia 測試幣(水龍頭:https://faucet.circle.com 或 Alchemy)。

## 0. 部署檢查
- `curl -s https://x402.workfern.com/ | grep "landing build"` → 版本應為本次 commit。
- 瀏覽器 **Ctrl+F5 硬刷新**,避免舊 JS 快取。

## 1. Payment required(狀態:Payment required)
1. 輸入已驗證的合約地址(例:`0x88e6A0c2dDD26FEEb64F039a2c41296FcB3f5640`)。
2. 點「Pay USDC to audit」。
3. **預期**:黃色「• Payment required」標籤 + 網路選單(主網在前、TESTNET 在後),每個按鈕顯示網路、`0.0001 USDC`(測試網)、`pay to:` 收款地址。
4. 若之前有提交過任務,上方應出現「You have a recently submitted audit. **Do not pay again**…」resume 卡(帶任務 ID 與報告連結)。

## 2. 顯式確認(金額/代幣/收款人/網路)
1. 點「Pay with Base Sepolia (testnet)」。
2. **預期**:「Confirm payment」面板:Network(含 CAIP-2)、Amount、Token USDC、Recipient,及「TESTNET (Base Sepolia)」徽章。
3. 點「Back」→ **預期**:回到網路選單,錢包**未開啟**、鏈**未切換**。再點別的網路 → 摘要顯示該網路。
4. 點「Approve & pay」→ 進入第 3 步。

## 3. Wallet approval pending → 簽名(狀態:Wallet approval pending)
1. **預期**:藍色「• Wallet approval pending」+「Opening your wallet…」;MetaMask 彈出。
2. 首次使用會先彈 connect/authorize,再彈切鏈確認(若錢包不在 84532),再彈 `eth_signTypedData_v4` 簽名。
3. **3a. 拒絕簽名**:在錢包按「拒絕」→ **預期**:紅色「• Payment failed」+「The request was cancelled in your wallet…」;資金未動。
4. **3b. 忽略彈窗**:不碰錢包 → 90 秒後逾時訊息;60 秒內再點別的鏈 → 「A wallet request is already open…」。
5. **3c. 錢包在錯誤鏈**:錢包切回 Ethereum 主網後再測 → 切鏈確認出現;拒絕切鏈 → 「Please switch your wallet to … and retry」。

## 4. Payment submitted → settled(狀態:Payment submitted → Payment settled)
1. 簽名後 **預期**:藍色「• Payment submitted」(「Payment signed. Submitting…」)。
2. 伺服器驗證+結算後 **預期**:綠色「• Payment settled」+「Audit dispatched!」+ Task ID + **Payment status: settled** + Transaction hash + Payer + Payment ref + 四個報告連結。
3. **驗收要點**:交易雜湊只在結算成功後出現(可對照 Sepolia explorer)。
4. Task ID 已寫入 sessionStorage(見第 9 步)。

## 5. 餘額不足
- 用沒有測試網 USDC 的帳號重測 → **預期**:「Payment rejected: Insufficient USDC balance on the selected network. Top up and retry.」(紅色 Payment failed)。

## 6. 重複提交(replay)
1. 完成一次支付後,同一分鐘內對同一 payload 再送(重新整理前用瀏覽器 DevTools 重送,或同 payload curl)→ **預期**:「This payment was already used (duplicate submission). The audit is not re-dispatched.」+ resume 卡。
2. 伺服器端保證:settle 只發生一次。

## 7. 授權過期
- 簽名後**等待 6 分鐘以上**再讓請求送出(maxTimeoutSeconds 到期)→ **預期**:「The signed payment authorization has expired. Refresh the terms and sign again.」(facilitator 端也會擋)。

## 8. Facilitator 錯誤(fail-closed)
- 模擬:暫時把 facilitator URL 指到不存在的 host 重啟服務(或等 x402.org 維護)→ **預期**:`facilitator_unreachable`/`facilitator_malformed` + 「Payment verification is temporarily unavailable… Your funds were not moved.」(**不是**「請再付一次」的 402)。
- 還原後重測應恢復。

## 9. 重新整理 / 中斷請求(狀態:Payment status unknown)
1. **重新整理測試**:支付成功後 F5 → 重新輸入地址點查詢 → resume 卡顯示上次任務(時間/網路)與免費報告連結;**不需要也不應該**再付一次。
2. **中斷請求測試**:簽名送出後立刻 DevTools → Network → Offline(或在送出瞬間關分頁)→ 回到頁面重測 → **預期**:琥珀色「• Payment status unknown」+「It may or may not have settled. Check before paying again…」+ 檢查指引;**絕不**顯示成功。
3. resume 卡點「Dismiss」可清除。

## 10. 主網/測試網隔離
- 主網按鈕的摘要徽章為「MAINNET (Base)」且註明「USDC will be transferred on Base mainnet」;測試網為「TESTNET (Base Sepolia)」。
- **頁面永不自動替你切換主網↔測試網**:切鏈只發生在你確認摘要後的錢包操作內。

## 11. 秘密不外洩
- 檢視頁面原始碼與 `web/dist/x402-bridge.js`:不得出現 `private_key`、API keys、Redis URL、GitHub token(自動化測試 `test_no_secrets_in_frontend` 已覆蓋)。

## 12. 對照自動化測試
```
.venv\Scripts\python.exe -m pytest tests/test_web_pages.py tests\test_payment_flow.py -p no:warnings -q
```
- `TestPaymentFlowStates::*`:七態狀態機、成功僅來自後端結算、交易雜湊不偽造、摘要確認、不自動切鏈、resume、error_code 對映、無秘密。
- `TestPaymentFlow(REST)`:402 條款、v1 拒絕、resource 綁定、過期、facilitator 失效、settle 成敗、replay。

## 狀態對照表
| 畫面標籤 | 觸發 | 顏色 |
|---|---|---|
| Payment required | 伺服器回 402 條款 / 摘要確認 | 黃 |
| Wallet approval pending | 開啟錢包(連接/切鏈/簽名) | 藍 |
| Payment submitted | 簽名完成、請求送出中 | 藍 |
| Payment verification pending | 等待後端驗證+結算 | 藍 |
| Payment settled | 後端回報 `payment.status=settled` | 綠 |
| Payment failed | 402/502/413/錢包拒絕 | 紅 |
| Payment status unknown | 送出後網路中斷,結果未知 | 琥珀 |
