package com.example.demo.service.impl;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.InputStreamResource;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import com.example.demo.domain.Contract;
import com.example.demo.domain.FileInfo;
import com.example.demo.domain.dto.FileStoreResult;
import com.example.demo.domain.response.ResultPaginationDTO;
import com.example.demo.repository.ContractRepository;
import com.example.demo.repository.FileRepository;
import com.example.demo.service.FileService;
import com.example.demo.service.criteria.FileSpecs;
import com.example.demo.util.error.IdInvalidException;
import com.example.demo.util.error.StorageException;

@Service
public class FileServiceImpl implements FileService {
	private final FileRepository fileRepository;
	private final ContractRepository contractRepository;

	/**
	 * @param fileRepository
	 * @param contractRepository
	 */
	public FileServiceImpl(FileRepository fileRepository, ContractRepository contractRepository) {
		this.fileRepository = fileRepository;
		this.contractRepository = contractRepository;
	}

	@Value("${hoanglong.upload-file.base-uri}")
	private String baseURI;

	@Value("${file.encryption.secret-key}")
	private String encryptionKey;

	private SecretKey generateKey() throws Exception {
		byte[] keyBytes = new byte[32];
		byte[] decodedKey = Base64.getDecoder().decode(encryptionKey);

		if (decodedKey.length != 32) {
			throw new StorageException("AES key must be 32 bytes (decoded from Base64). Found: " + decodedKey.length);
		}

		System.arraycopy(decodedKey, 0, keyBytes, 0, 32);

		return new SecretKeySpec(keyBytes, "AES");
	}

	public void createDirectory(String folder) throws URISyntaxException {
		URI uri = new URI(folder);
		Path path = Paths.get(uri);
		File file = new File(path.toString());
		if (!file.isDirectory()) {
			try {
				Files.createDirectory(file.toPath());
				System.out.println(">>> CREATE NEW DIRECTORY SUCCESSFULLY, PATH = " + file.toPath());
			} catch (IOException e) {

				e.printStackTrace();
			}
		} else {
			System.out.println(">>> SKIP MAKING DIRECTORY, ALREADY EXISTED");
		}

	}

	public FileStoreResult store(MultipartFile file) throws URISyntaxException, IOException, StorageException {
		String finalName = System.currentTimeMillis() + "-" + file.getOriginalFilename();
		URI uri = new URI(baseURI + "/" + finalName);
		Path path = Paths.get(uri);
		try {
			// Encrypt file content
			byte[] encryptedContent = encryptLargeFile(file.getBytes());
			String checksum = calculateChecksum(encryptedContent);
			Files.write(path, encryptedContent);
			return new FileStoreResult(finalName, checksum);
		} catch (Exception e) {
			throw new StorageException(e.getMessage());
		}
	}

	public long getFileLength(String fileName) throws URISyntaxException {
		URI uri = new URI(baseURI + "/" + fileName);
		Path path = Paths.get(uri);
		File file = new File(path.toString());

		if (!file.exists() || file.isDirectory()) {
			return 0;
		}
		return file.length();
	}

	public InputStreamResource getResource(long id)
			throws StorageException, URISyntaxException {
		// TODO Auto-generated method stub
		FileInfo file = this.fileRepository.findById(id)
				.orElseThrow(() -> new StorageException("File not found with ID: " + id));

		if (file.isDeleted()) {
			throw new StorageException("File has been deleted");
		}

		String fileName = file.getPath();
		URI uri = new URI(baseURI + "/" + fileName);
		Path path = Paths.get(uri);

		if (!Files.exists(path)) {
			throw new StorageException("Physical file not found at: " + path);
		}

		try {
			byte[] encryptedContent = Files.readAllBytes(path);
			String currentChecksum = calculateChecksum(encryptedContent);
			if (!currentChecksum.equals(file.getChecksum())) {
				throw new StorageException("File integrity check failed");
			}
			byte[] decryptedContent = decryptFile(encryptedContent);
			return new InputStreamResource(new ByteArrayInputStream(decryptedContent));
		} catch (NoSuchAlgorithmException e) {
			throw new StorageException("Failed to calculate checksum");
		} catch (Exception e) {
			throw new StorageException(e.getMessage());
		}
	}

	public FileInfo handleUpload(MultipartFile file, FileInfo postmanFileInfo)
			throws IdInvalidException, StorageException, URISyntaxException, IOException {
		if (fileRepository.existsByFileIdAndDeletedFalse(postmanFileInfo.getFileId())) {
			throw new IdInvalidException("Item ID = " + postmanFileInfo.getFileId() + "already exists");
		}
		Contract contract = this.contractRepository
				.findByContractIdAndDeletedFalse(postmanFileInfo.getContract().getContractId()).orElse(null);
		if (contract == null) {
			throw new IdInvalidException(
					"Contract ID = " + postmanFileInfo.getContract().getContractId() + " doesn't exist!");
		}
		postmanFileInfo.setContract(contract);

		if (file == null || file.isEmpty()) {
			throw new StorageException("File is empty. Please upload a file");
		}
		String fileName = file.getOriginalFilename().replace("%20", " ");

		postmanFileInfo.setName(fileName);

		List<String> allowedExtensions = Arrays.asList("pdf", "jpg", "jpeg", "png", "doc", "docx");
		boolean isValid = allowedExtensions.stream().anyMatch(extension -> fileName.toLowerCase().endsWith(extension));
		if (!isValid) {
			throw new StorageException("Invalid file extension. Only allow " + allowedExtensions.toString());
		}

		String tail = "";
		if (fileName != null && fileName.contains(".")) {
			tail = fileName.substring(fileName.lastIndexOf(".") + 1).toLowerCase();
		}
		postmanFileInfo.setType(tail);

		createDirectory(baseURI);
		FileStoreResult result = store(file);

		postmanFileInfo.setSize(getFileLength(result.getFileName()));
		postmanFileInfo.setDeleted(false);
		postmanFileInfo.setPath(result.getFileName());
		postmanFileInfo.setChecksum(result.getChecksum());

		return this.fileRepository.save(postmanFileInfo);

	}

	private String calculateChecksum(byte[] content) throws NoSuchAlgorithmException {
		MessageDigest digest = MessageDigest.getInstance("SHA-256");
		byte[] hash = digest.digest(content);
		return Base64.getEncoder().encodeToString(hash);
	}

	public void handleDelete(long id) throws IdInvalidException {
		FileInfo fileInfo = this.fileRepository.findById(id).orElse(null);
		if (fileInfo == null) {
			throw new IdInvalidException("File ID = " + id + " doesn't exist!");
		}
		fileInfo.setDeleted(true);
		this.fileRepository.save(fileInfo);
	}

	public ResultPaginationDTO handleFetchAllFiles(Specification<FileInfo> specification, Pageable pageable) {
		Specification<FileInfo> finalSpec = FileSpecs.matchDeletedFalse();
		if (specification != null) {
			finalSpec = finalSpec.and(specification);
		}
		Page<FileInfo> page = this.fileRepository.findAll(finalSpec, pageable);
		ResultPaginationDTO result = new ResultPaginationDTO();
		ResultPaginationDTO.Meta meta = new ResultPaginationDTO.Meta();

		meta.setPage(pageable.getPageNumber() + 1);
		meta.setPageSize(pageable.getPageSize());
		meta.setPages(page.getTotalPages());
		meta.setTotal(page.getTotalElements());

		result.setMeta(meta);

		result.setResult(page.getContent());

		return result;
	}

	public FileInfo findById(long id) throws IdInvalidException, StorageException {
		FileInfo fileInfo = this.fileRepository.findById(id)
				.orElseThrow(() -> new IdInvalidException("File ID = " + id + " doesn't exist!"));

		if (fileInfo.isDeleted()) {
			throw new StorageException("File has been deleted");
		}
		return fileInfo;

	}

	private byte[] encryptLargeFile(byte[] fileContent) throws Exception {
		SecretKey key = generateKey();
		Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, key);

		int chunkSize = 16 * 1024 * 1024;
		int inputPos = 0;
		int outputPos = 0;

		byte[] result = new byte[fileContent.length + 32];

		while (inputPos < fileContent.length) {
			int length = Math.min(chunkSize, fileContent.length - inputPos);
			byte[] chunk = Arrays.copyOfRange(fileContent, inputPos, inputPos + length);
			byte[] encryptedChunk = cipher.update(chunk);

			if (encryptedChunk != null) {
				System.arraycopy(encryptedChunk, 0, result, outputPos, encryptedChunk.length);
				outputPos += encryptedChunk.length;
			}

			inputPos += length;
		}

		byte[] finalBlock = cipher.doFinal();
		if (finalBlock != null) {
			System.arraycopy(finalBlock, 0, result, outputPos, finalBlock.length);
			outputPos += finalBlock.length;
		}

		return Arrays.copyOf(result, outputPos);
	}

	private byte[] decryptFile(byte[] encryptedData) throws Exception {
		SecretKey key = generateKey();
		Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
		cipher.init(Cipher.DECRYPT_MODE, key);

		int chunkSize = 16 * 1024 * 1024;
		int inputPos = 0;
		int outputPos = 0;

		byte[] result = new byte[encryptedData.length + 32];

		while (inputPos < encryptedData.length) {
			int length = Math.min(chunkSize, encryptedData.length - inputPos);
			byte[] chunk = Arrays.copyOfRange(encryptedData, inputPos, inputPos + length);
			byte[] decryptedChunk = cipher.update(chunk);

			if (decryptedChunk != null) {
				System.arraycopy(decryptedChunk, 0, result, outputPos, decryptedChunk.length);
				outputPos += decryptedChunk.length;
			}

			inputPos += length;
		}

		byte[] finalBlock = cipher.doFinal();
		if (finalBlock != null) {
			System.arraycopy(finalBlock, 0, result, outputPos, finalBlock.length);
			outputPos += finalBlock.length;
		}

		return Arrays.copyOf(result, outputPos);
	}

}