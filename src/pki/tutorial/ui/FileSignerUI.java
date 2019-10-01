/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package pki.tutorial.ui;

import java.awt.event.ItemEvent;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.AbstractListModel;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.swing.UIManager;
import javax.swing.UnsupportedLookAndFeelException;
import pki.tutorial.certificate.CertificateFactory;
import pki.tutorial.keystore.KeyStoreHolder;
import pki.tutorial.keystore.KeyStoreHolder.KeyStoreHolderType;
import pki.tutorial.keystore.KeyStoreHolderFactory;
import pki.tutorial.utils.FileManager;

/**
 *
 * @author mohamed
 */
public class FileSignerUI extends javax.swing.JFrame {

    private static final String KS_SELECTION_ERROR_MSG = "Please choose .p12 file !";

    private final String MSG_ERROR_NO_FILE_SELECTED = "Please select a file first !!";
    private final String MSG_ERROR_NO_SIGN_FILE = "Can not find the signature file !!";

    private final String MSG_SUCCESS_SIGNED = "Verified successfully, File is signed by ";
    private final String MSG_FAIL_SIGNED = "Fail to verify, File is not signed by ";
    private final String MSG_ERROR_PASSWORD = "Please select a keystore and enter its correct password !!";
    private final String MSG_ERROR_SELECT_A_KEY = "Please select a key !";
    private final String MSG_ERROR_SELECT_A_FILE = "Please select a file first !!";
    private final String MSG_INFO_NO_KEYS_IN_KEYSTORE = "Keystore is empty !";
    private final String MSG_SUCCESS_SIGN = "Signature generated successfully !";
    private final String MSG_ERROR_NOT_A_PRIVATE_KEY = "Error the selected key is not a private key !";
    private final String MSG_ERROR_NOT_A_PUBLIC_KEY = "Error the selected key is not a public key !";
    private final FileManager mFileManager = new FileManager();
    private List<String> keysAliasList;
    private String mSelectedAlias;
    private File mKeyStoreFile;
    private File mFile;
    private KeyStoreHolder mKeystore;
    private KeyStoreHolderType currentSelectedKeyStoreType;
    private KeyStoreHolderFactory keyStoreHolderFactory;
    private CertificateFactory certificateFactory;

    /**
     * Creates new form MainUI
     */
    public FileSignerUI() {
        initComponents();
        keyStoreHolderFactory = new KeyStoreHolderFactory();
               certificateFactory=new CertificateFactory();
        addKeylistListener();
        //  ksTypeSpinner.
    }

    private void addKeylistListener() {
        ksTypeList.addItemListener((ItemEvent e) -> {
            if (e.getStateChange() == ItemEvent.SELECTED) {
                // System.out.println("" + e.getItem().toString());
                currentSelectedKeyStoreType = KeyStoreHolderType.valueOf(e.getItem().toString());

                if (currentSelectedKeyStoreType.equals(KeyStoreHolderType.P12)) {
                    ksBrowse.setEnabled(true);
                } else {
                    ksBrowse.setEnabled(false);
                }

            }

        });
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        btnLogin = new javax.swing.JButton();
        btnSign = new javax.swing.JButton();
        ksPassword = new javax.swing.JPasswordField();
        jLabel1 = new javax.swing.JLabel();
        jScrollPane1 = new javax.swing.JScrollPane();
        keyList = new javax.swing.JList();
        ksBrowse = new javax.swing.JButton();
        jLabel2 = new javax.swing.JLabel();
        jLabel3 = new javax.swing.JLabel();
        jLabel4 = new javax.swing.JLabel();
        jLabel5 = new javax.swing.JLabel();
        fileBrowse = new javax.swing.JButton();
        jLabel6 = new javax.swing.JLabel();
        fileLabel = new javax.swing.JLabel();
        btnVerify = new javax.swing.JButton();
        jLabel8 = new javax.swing.JLabel();
        ksLabel = new javax.swing.JLabel();
        ksTypeList = new javax.swing.JComboBox();
        btnImport = new javax.swing.JButton();
        btnDelete = new javax.swing.JButton();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);
        setBackground(new java.awt.Color(255, 255, 204));

        btnLogin.setText("Login");
        btnLogin.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnLoginActionPerformed(evt);
            }
        });

        btnSign.setFont(new java.awt.Font("Tahoma", 1, 11)); // NOI18N
        btnSign.setText("Sign");
        btnSign.setEnabled(false);
        btnSign.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnSignActionPerformed(evt);
            }
        });

        jLabel1.setText("Password :");

        keyList.setEnabled(false);
        jScrollPane1.setViewportView(keyList);

        ksBrowse.setText("Browse");
        ksBrowse.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                ksBrowseActionPerformed(evt);
            }
        });

        jLabel2.setFont(new java.awt.Font("Tahoma", 1, 24)); // NOI18N
        jLabel2.setForeground(new java.awt.Color(0, 0, 255));
        jLabel2.setText("SIGNER");

        jLabel3.setText("Created by : Mohammed Almissbah");

        jLabel4.setText("Keystore type:");

        jLabel5.setText("Stored keys:");

        fileBrowse.setText("Browse");
        fileBrowse.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                fileBrowseActionPerformed(evt);
            }
        });

        jLabel6.setText("Please select keystore and press login");

        fileLabel.setText("Choose input file ");

        btnVerify.setFont(new java.awt.Font("Tahoma", 1, 11)); // NOI18N
        btnVerify.setForeground(new java.awt.Color(0, 153, 51));
        btnVerify.setText("Verify");
        btnVerify.setEnabled(false);
        btnVerify.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnVerifyActionPerformed(evt);
            }
        });

        jLabel8.setText("Mohammed.almissbah@hotmail.com");

        ksLabel.setText("Select a keystore");

        ksTypeList.setModel(new javax.swing.DefaultComboBoxModel(new String[] { KeyStoreHolderType.P12.name(), KeyStoreHolderType.ST3TOKEN.name(), KeyStoreHolderType.BIT4ID.name() }));

        btnImport.setText("Import");
        btnImport.setEnabled(false);
        btnImport.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnImportActionPerformed(evt);
            }
        });

        btnDelete.setText("Delete");
        btnDelete.setEnabled(false);
        btnDelete.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnDeleteActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addGap(3, 3, 3)
                        .addComponent(jLabel4))
                    .addGroup(layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                            .addComponent(ksPassword, javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jLabel6, javax.swing.GroupLayout.DEFAULT_SIZE, 185, Short.MAX_VALUE)
                            .addGroup(layout.createSequentialGroup()
                                .addComponent(fileLabel, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                .addGap(18, 18, 18)
                                .addComponent(fileBrowse))
                            .addGroup(javax.swing.GroupLayout.Alignment.LEADING, layout.createSequentialGroup()
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                    .addComponent(jLabel1)
                                    .addComponent(btnLogin, javax.swing.GroupLayout.PREFERRED_SIZE, 93, javax.swing.GroupLayout.PREFERRED_SIZE))
                                .addGap(0, 0, Short.MAX_VALUE))
                            .addComponent(ksTypeList, 0, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                        .addGap(18, 18, 18)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jLabel5)
                            .addGroup(layout.createSequentialGroup()
                                .addComponent(ksLabel)
                                .addGap(18, 18, 18)
                                .addComponent(ksBrowse))
                            .addGroup(layout.createSequentialGroup()
                                .addComponent(btnImport)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(btnDelete))
                            .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 170, javax.swing.GroupLayout.PREFERRED_SIZE))))
                .addGap(17, 17, 17))
            .addGroup(layout.createSequentialGroup()
                .addGap(151, 151, 151)
                .addComponent(jLabel2)
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(btnSign, javax.swing.GroupLayout.PREFERRED_SIZE, 153, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(btnVerify, javax.swing.GroupLayout.PREFERRED_SIZE, 138, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 62, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                            .addComponent(jLabel8)
                            .addComponent(jLabel3))
                        .addGap(68, 68, 68)))
                .addGap(46, 46, 46))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jLabel2)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 11, Short.MAX_VALUE)
                .addComponent(jLabel4)
                .addGap(8, 8, 8)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addGap(25, 25, 25)
                        .addComponent(jLabel5)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addGroup(layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(ksLabel)
                            .addComponent(ksBrowse)
                            .addComponent(ksTypeList, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(jLabel1)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(ksPassword, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(jLabel6)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(btnLogin)
                        .addGap(18, 18, 18)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(fileBrowse)
                            .addComponent(fileLabel))))
                .addGap(2, 2, 2)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(btnImport)
                    .addComponent(btnDelete))
                .addGap(23, 23, 23)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(btnSign)
                    .addComponent(btnVerify))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(jLabel3)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jLabel8)
                .addContainerGap())
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void enableSignAndVerify() {
        btnSign.setEnabled(true);
        btnVerify.setEnabled(true);
        keyList.setEnabled(true);
        btnImport.setEnabled(true);
        btnDelete.setEnabled(true);
    }

    private void disableSignAndVerify() {
        btnSign.setEnabled(false);
        btnVerify.setEnabled(false);
        keyList.setEnabled(false);
        btnImport.setEnabled(false);
        btnDelete.setEnabled(false);
    }
    private void fileBrowseActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_fileBrowseActionPerformed
        JFileChooser fc = new JFileChooser();
        int i = fc.showOpenDialog(this);
        if (i == JFileChooser.APPROVE_OPTION) {
            mFile = fc.getSelectedFile();
            fileLabel.setText(mFile.getName());
        }
        // TODO add your handling code here:
    }//GEN-LAST:event_fileBrowseActionPerformed

    private void ksBrowseActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_ksBrowseActionPerformed
        // TODO add your handling code here:
        JFileChooser fc = new JFileChooser();
        int i = fc.showOpenDialog(this);
        File selectedFile = fc.getSelectedFile();
        if (i == JFileChooser.APPROVE_OPTION) {
            if (selectedFile.getName().contains("p12")
                    || selectedFile.getName().contains("P12")) {
                mKeyStoreFile = selectedFile;
                ksLabel.setText(mKeyStoreFile.getName());
            } else {

                showMessage(KS_SELECTION_ERROR_MSG);
            }
        }
    }//GEN-LAST:event_ksBrowseActionPerformed

    private void btnLoginActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnLoginActionPerformed
        // TODO add your handling code here:
        if (ksPassword.isEnabled()) {
            buildKeyStore();

        } else {
            resetApp();
        }
    }//GEN-LAST:event_btnLoginActionPerformed
    private void buildKeyStore() {

        try {
            if (currentSelectedKeyStoreType.equals(KeyStoreHolderType.P12)) {
                if (mKeyStoreFile != null) {
                    mKeystore = keyStoreHolderFactory.createPkcs12KeyStore(mKeyStoreFile.getPath());
                    initKeystore();
                } else {
                    showMessage(MSG_ERROR_NO_FILE_SELECTED);
                }
            } else {
                mKeystore = keyStoreHolderFactory.createPkcs11KeyStore(currentSelectedKeyStoreType);
                initKeystore();
            }

        } catch (Exception ex) {
            showMessage(MSG_ERROR_PASSWORD);
        }

    }

    private void initKeystore() throws Exception {
        String ksPasswordText = ksPassword.getText();

        mKeystore.init(ksPasswordText);
        showMessage(ksPasswordText);
        if (mKeystore.isInitialized()) {
            btnLogin.setText("Logout");
            ksPassword.setEnabled(false);
            loadKeyList();
        }
    }

    private void loadKeyList() {
        try {
            keysAliasList = mKeystore.getAliases();
            if (keysAliasList.size() > 0) {
                enableSignAndVerify();
            } else {
                showMessage(MSG_INFO_NO_KEYS_IN_KEYSTORE);
                disableSignAndVerify();
            }
            keyList.setModel(new AbstractListModel() {
                @Override
                public int getSize() {
                    return keysAliasList.size();
                }

                @Override
                public Object getElementAt(int index) {
                    return keysAliasList.get(index);
                }
            });
        } catch (KeyStoreException ex) {
            showMessage(MSG_INFO_NO_KEYS_IN_KEYSTORE);
            disableSignAndVerify();
        }
    }

    private void resetApp() {
        ksPassword.setEnabled(true);
        ksPassword.setText("");
        mKeystore = null;
        btnLogin.setText("Login");
        disableSignAndVerify();
    }

    private String generateSignatureFilePath() {
        return mFile.getPath() + ".sign";

    }
    private void btnSignActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnSignActionPerformed
        // TODO add your handling code here:

        try {

            if (keyList.getSelectedValue() != null) {
                mSelectedAlias = keyList.getSelectedValue().toString();
                if (mFile != null) {
                    if (mKeystore.isEntryExist(mSelectedAlias)) {
                        byte[] bytesFromFile = mFileManager.readFile(mFile.getPath());
                        byte[] sinature = mKeystore.signData(mSelectedAlias, bytesFromFile);
                        mFileManager.writeFile(sinature, generateSignatureFilePath());
                        if (isSignFileGenerated()) {
                            showMessage(MSG_SUCCESS_SIGN);
                        }
                    } else {
                        showMessage(MSG_ERROR_NOT_A_PRIVATE_KEY);
                    }
                } else {
                    showMessage(MSG_ERROR_SELECT_A_FILE);
                }
            } else {
                showMessage(MSG_ERROR_SELECT_A_KEY);
            }
        } catch (IOException ex) {
            Logger.getLogger(FileSignerUI.class.getName()).log(Level.SEVERE, null, ex);
        } catch (Exception ex) {
            Logger.getLogger(FileSignerUI.class.getName()).log(Level.SEVERE, null, ex);
        }

    }//GEN-LAST:event_btnSignActionPerformed
    private boolean isSignFileGenerated() {
        File signFile = new File(generateSignatureFilePath());
        return signFile.exists();
    }
    private void btnVerifyActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnVerifyActionPerformed
        // TODO add your handling code here:

        if (mFile != null && mFile.exists()) {
            File signatureFile = new File(generateSignatureFilePath());
            if (signatureFile != null && signatureFile.exists()) {
                verifySignature(signatureFile);
            } else {
                showMessage(MSG_ERROR_NO_SIGN_FILE);
            }
        } else {
            showMessage(MSG_ERROR_NO_FILE_SELECTED);
        }
    }//GEN-LAST:event_btnVerifyActionPerformed

    private void btnDeleteActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnDeleteActionPerformed
        try {
            if (keyList.getSelectedValue() != null) {
                mSelectedAlias = keyList.getSelectedValue().toString();
                mKeystore.deleteEntry(mSelectedAlias);
                loadKeyList();
            }

        } catch (KeyStoreException ex) {
            Logger.getLogger(FileSignerUI.class.getName()).log(Level.SEVERE, null, ex);
        }
    }//GEN-LAST:event_btnDeleteActionPerformed

    private void btnImportActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnImportActionPerformed
        // TODO add your handling code here:

        JFileChooser fc = new JFileChooser();
        int i = fc.showOpenDialog(this);
        if (i == JFileChooser.APPROVE_OPTION) {
            File fileToImport = fc.getSelectedFile();
            Certificate crt;
     
            try {
                crt = certificateFactory.createCertificateFromFile(fileToImport.getPath());

                mKeystore.importCertificate(((X509Certificate) crt).getSubjectDN().toString(), ((Certificate) crt));
                loadKeyList();
            } catch (FileNotFoundException | CertificateException | KeyStoreException ex) {
                Logger.getLogger(FileSignerUI.class.getName()).log(Level.SEVERE, null, ex);
            }

        }
    }//GEN-LAST:event_btnImportActionPerformed
    private void verifySignature(File signatureFile) {

        if (keyList.getSelectedValue() != null) {
            String keyAlias = keyList.getSelectedValue().toString();
            try {
                byte[] signature = mFileManager.readFile(signatureFile.getPath());
                byte[] fileBytes = mFileManager.readFile(mFile.getPath());
                boolean isVerified = mKeystore.verifySignature(keyAlias, fileBytes, signature);
                if (isVerified) {
                    showMessage(MSG_SUCCESS_SIGNED + " " + keyAlias);
                } else {
                    showMessage(MSG_FAIL_SIGNED + " " + keyAlias);
                }

            } catch (Exception ex) {
                showMessage(MSG_FAIL_SIGNED + " " + keyAlias);
            }
        } else {
            showMessage(MSG_ERROR_SELECT_A_KEY);
        }
    }

    private void showMessage(String msg) {
        JOptionPane.showMessageDialog(this, msg);
    }

    /**
     * @param args the command line arguments
     */
    public static void main(String args[]) {
        /* Set the Nimbus look and feel */
        //<editor-fold defaultstate="collapsed" desc=" Look and feel setting code (optional) ">
        /* If Nimbus (introduced in Java SE 6) is not available, stay with the default look and feel.
         * For details see http://download.oracle.com/javase/tutorial/uiswing/lookandfeel/plaf.html 
         */
        try {
            for (javax.swing.UIManager.LookAndFeelInfo info : javax.swing.UIManager.getInstalledLookAndFeels()) {
                if ("Nimbus".equals(info.getName())) {
                    javax.swing.UIManager.setLookAndFeel(info.getClassName());
                    break;
                }
            }
        } catch (ClassNotFoundException | InstantiationException | IllegalAccessException | javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(FileSignerUI.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        java.awt.EventQueue.invokeLater(() -> {
            try {
                UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
                new FileSignerUI().setVisible(true);
            } catch (ClassNotFoundException | InstantiationException | IllegalAccessException | UnsupportedLookAndFeelException ex) {
                Logger.getLogger(FileSignerUI.class.getName()).log(Level.SEVERE, null, ex);

            }
        });
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton btnDelete;
    private javax.swing.JButton btnImport;
    private javax.swing.JButton btnLogin;
    private javax.swing.JButton btnSign;
    private javax.swing.JButton btnVerify;
    private javax.swing.JButton fileBrowse;
    private javax.swing.JLabel fileLabel;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JLabel jLabel4;
    private javax.swing.JLabel jLabel5;
    private javax.swing.JLabel jLabel6;
    private javax.swing.JLabel jLabel8;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JList keyList;
    private javax.swing.JButton ksBrowse;
    private javax.swing.JLabel ksLabel;
    private javax.swing.JPasswordField ksPassword;
    private javax.swing.JComboBox ksTypeList;
    // End of variables declaration//GEN-END:variables

}
