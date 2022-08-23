package br.com.dh.brecho.service;

import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import br.com.dh.brecho.model.Produto;
import br.com.dh.brecho.repository.ProdutoRepository;

@Service
public class ProdutoService {

	@Autowired
	private ProdutoRepository produtoRepository;

	public List<Produto> getAll() {

		return produtoRepository.findAll();

	}

	public Optional<Produto> getById(Long id) {

		return produtoRepository.findById(id);

	}

	public Produto post(Produto produto) {

		return produtoRepository.save(produto);

	}

	public Optional<Produto> put(Produto produto) {

		if (produtoRepository.existsById(produto.getId()))
			return Optional.ofNullable(produtoRepository.save(produto));
		
		return Optional.empty();
		

	}

	public void delete(Long id) {

		if (produtoRepository.existsById(id))
			produtoRepository.deleteById(id);

	}

}
