package io.github.sillwork.blindcrypt.spring.test;

import io.github.sillwork.blindcrypt.core.Normalization;
import io.github.sillwork.blindcrypt.spring.annotation.BlindIndex;
import io.github.sillwork.blindcrypt.spring.listener.BlindIndexListener;
import io.github.sillwork.blindcrypt.spring.model.EncryptedBytes;
import io.github.sillwork.blindcrypt.spring.model.EncryptedText;
import jakarta.persistence.Entity;
import jakarta.persistence.EntityListeners;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.MappedSuperclass;
import jakarta.persistence.Table;
import jakarta.persistence.Version;

@MappedSuperclass
@EntityListeners(BlindIndexListener.class)
abstract class BaseDocument {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Version
    private Long version;

    public Long getId() { return id; }
    public Long getVersion() { return version; }
}

@Entity
@Table(name = "test_documents")
public class TestDocument extends BaseDocument {

    // Naming strategy should translate:
    // docTitle.encryptedValue -> doc_title
    // docTitle.blindIndex -> doc_title_bidx
    @BlindIndex(name = "doc_title", normalization = Normalization.TRIM_CASE_INSENSITIVE)
    private EncryptedText docTitle;

    // Binary columns without @AttributeOverride, multiple byte columns
    @BlindIndex(name = "doc_fingerprint", normalization = Normalization.NONE)
    private EncryptedBytes fingerprint;

    @BlindIndex(name = "doc_signature", normalization = Normalization.NONE)
    private EncryptedBytes signature;

    protected TestDocument() { }

    public TestDocument(String title, byte[] fingerprint, byte[] signature) {
        this.docTitle = EncryptedText.of(title);
        this.fingerprint = EncryptedBytes.of(fingerprint);
        this.signature = EncryptedBytes.of(signature);
    }

    public String getDocTitle() { return EncryptedText.valueOf(docTitle); }
    public void setDocTitle(String title) { this.docTitle = EncryptedText.update(this.docTitle, title); }

    public byte[] getFingerprint() { return EncryptedBytes.valueOf(fingerprint); }
    public void setFingerprint(byte[] fp) { this.fingerprint = EncryptedBytes.update(this.fingerprint, fp); }

    public byte[] getSignature() { return EncryptedBytes.valueOf(signature); }
    public void setSignature(byte[] sig) { this.signature = EncryptedBytes.update(this.signature, sig); }
}
