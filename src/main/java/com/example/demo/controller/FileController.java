package com.example.demo.controller;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.URISyntaxException;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.InputStreamResource;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import com.example.demo.domain.FileInfo;
import com.example.demo.domain.response.ResultPaginationDTO;
import com.example.demo.service.FileService;
import com.example.demo.util.annotation.ApiMessage;
import com.example.demo.util.error.IdInvalidException;
import com.example.demo.util.error.StorageException;
import com.turkraft.springfilter.boot.Filter;

import org.springframework.web.bind.annotation.GetMapping;

@RestController
@RequestMapping("/api/v1")
public class FileController {

	@Value("${hoanglong.upload-file.base-uri}")
	private String baseURI;

	private final FileService fileService;

	/**
	 * @param fileService
	 */
	public FileController(FileService fileService) {
		this.fileService = fileService;
	}

	@PostMapping("/files")
	@ApiMessage("Upload single file")
	public ResponseEntity<FileInfo> uploadFile(
			@RequestParam(name = "file", required = false) MultipartFile file, @RequestBody FileInfo postmanFileInfo)
			throws URISyntaxException, IOException, StorageException, IdInvalidException {

		return ResponseEntity.status(HttpStatus.CREATED).body(fileService.handleUpload(file, postmanFileInfo));
	}

	@DeleteMapping("/files/{id}")
	@ApiMessage("Delete a file")
	public ResponseEntity<Void> deleteFile(@PathVariable("id") long id) throws IdInvalidException {
		fileService.handleDelete(id);
		return ResponseEntity.ok(null);
	}

	@GetMapping("/files")
	@ApiMessage("Get all files")
	public ResponseEntity<ResultPaginationDTO> getAllFiles(@Filter Specification<FileInfo> specification,
			Pageable pageable) {
		return ResponseEntity.ok(this.fileService.handleFetchAllFiles(specification, pageable));
	}

	@GetMapping("/files/{id}/download")
	@ApiMessage("Download a file")
	public ResponseEntity<InputStreamResource> downloadFile(@PathVariable("id") long id)
			throws URISyntaxException, StorageException, IdInvalidException {

		// Get file info
		FileInfo fileInfo = fileService.findById(id);

		// Get file resource
		InputStreamResource resource = fileService.getResource(id);

		// Set headers
		HttpHeaders headers = new HttpHeaders();
		headers.add(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=" + fileInfo.getName());
		headers.add(HttpHeaders.CACHE_CONTROL, "no-cache, no-store, must-revalidate");
		headers.add(HttpHeaders.PRAGMA, "no-cache");
		headers.add(HttpHeaders.EXPIRES, "0");

		// Return response
		return ResponseEntity.ok()
				.headers(headers)
				.contentType(MediaType.APPLICATION_OCTET_STREAM)
				.body(resource);
	}

}
