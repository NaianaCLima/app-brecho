package br.com.dh.brecho.controller;

import java.util.List;

import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import br.com.dh.brecho.model.Setor;
import br.com.dh.brecho.service.SetorService;

@RestController	
@RequestMapping("/setores")
@CrossOrigin(origins = "*", allowedHeaders = "*")
public class SetorController {
	
	@Autowired
	private SetorService setorService;

	@GetMapping
	public ResponseEntity<List<Setor>> getAll(){
		return ResponseEntity.ok(setorService.getAll());
	}
    
	@GetMapping("/{id}")
	public ResponseEntity<Setor> getById(@PathVariable Long id){
		return setorService.getById(id)
                .map(resposta -> ResponseEntity.ok(resposta))
                .orElse(ResponseEntity.notFound().build());
	}
	
	
	@PostMapping
	public ResponseEntity<Setor> postProduto(@Valid @RequestBody Setor setor){
		return ResponseEntity.status(HttpStatus.CREATED).body(setorService.post(setor));
	}
	
	@PutMapping
	public ResponseEntity<Setor> putProduto(@Valid @RequestBody Setor setor) {
		return setorService.put(setor)
                .map(resposta -> ResponseEntity.status(HttpStatus.OK).body(setor))
                .orElse(ResponseEntity.notFound().build());
	}

	@DeleteMapping("/{id}")
	public void delete(@PathVariable Long id) {
		setorService.delete(id);
	}
	
}

