package com.hedera.services.txns.schedule;

/*-
 * ‌
 * Hedera Services Node
 * ​
 * Copyright (C) 2018 - 2020 Hedera Hashgraph, LLC
 * ​
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * ‍
 */

import com.hedera.services.ledger.HederaLedger;
import com.hedera.services.legacy.core.jproto.JKey;
import com.hedera.services.legacy.core.jproto.JKeyList;
import com.hedera.services.legacy.core.jproto.JThresholdKey;
import com.hedera.services.legacy.exception.InvalidAccountIDException;
import com.hedera.services.legacy.exception.InvalidKeysForPartiesException;
import com.hedera.services.sigs.order.HederaSigningOrder;
import com.hedera.services.sigs.order.SigStatusOrderResultFactory;
import com.hedera.services.sigs.verification.InvalidPayerAccountException;
import com.hedera.services.store.schedule.ScheduleStore;
import com.hederahashgraph.api.proto.java.ScheduleID;
import com.hederahashgraph.api.proto.java.TransactionBody;

import java.util.List;
import java.util.Set;

import static com.hedera.services.keys.DefaultActivationCharacteristics.DEFAULT_ACTIVATION_CHARACTERISTICS;
import static com.hedera.services.legacy.core.jproto.JKey.equalUpToDecodability;

public abstract class ScheduleReadyForExecution {
    public final static SigStatusOrderResultFactory PRE_HANDLE_SUMMARY_FACTORY =
            new SigStatusOrderResultFactory(false);

    private final HederaLedger ledger;
    protected final HederaSigningOrder signingOrder;
    protected final ScheduleStore store;

    protected ScheduleReadyForExecution(
            HederaLedger ledger,
            HederaSigningOrder signingOrder,
            ScheduleStore store) {
        this.ledger = ledger;
        this.signingOrder = signingOrder;
        this.store = store;
    }

    protected boolean readyForExecution(ScheduleID scheduleID) throws Exception {
        var schedule = store.get(scheduleID);
        var signers = schedule.signers();

        var transaction = TransactionBody.parseFrom(schedule.transactionBody());
        var payerAccount = schedule.payer().toGrpcAccountId();

        if (!ledger.exists(schedule.payer().toGrpcAccountId())) {
            throw new InvalidPayerAccountException();
        }

        var payerPubKey = ledger.get(payerAccount).getKey();

        if (!keyFound(payerPubKey, signers)) {
            return false;
        }

        var result = signingOrder.keysForOtherParties(transaction, PRE_HANDLE_SUMMARY_FACTORY);
        if (result.hasErrorReport()) {
            var error = result.getErrorReport();
            if (error.hasAccountId()) {
                throw new InvalidAccountIDException(error.getAccountId(), new Throwable());
            } else {
                throw new InvalidKeysForPartiesException(error.toString());
            }
        }

        return otherPartiesKeysAreFound(signers, result.getOrderedKeys());
    }

    private static boolean keyFound(JKey key, Set<JKey> set) {
        if (!key.hasKeyList() && !key.hasThresholdKey()) {
            return contains(set, key);
        } else {
            List<JKey> children = key.hasKeyList()
                    ? key.getKeyList().getKeysList()
                    : key.getThresholdKey().getKeys().getKeysList();
            int keysNeededCount = key.hasKeyList()
                    ? DEFAULT_ACTIVATION_CHARACTERISTICS.sigsNeededForList((JKeyList) key)
                    : DEFAULT_ACTIVATION_CHARACTERISTICS.sigsNeededForThreshold((JThresholdKey) key);
            return children.stream().mapToInt(child -> keyFound(child, set) ? 1 : 0).sum() >= keysNeededCount;
        }
    }

    private static boolean otherPartiesKeysAreFound(Set<JKey> set, List<JKey> otherPartiesKeys) {
        for (JKey otherPartyKey: otherPartiesKeys) {
            if (!keyFound(otherPartyKey, set)) {
                return false;
            }
        }

        return true;
    }

    private static boolean contains(Set<JKey> set, JKey key) {
        for (JKey jKey : set) {
            if (equalUpToDecodability(jKey, key)) {
                return true;
            }
        }

        return false;
    }
}
